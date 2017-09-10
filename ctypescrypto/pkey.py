"""
This module provides interface for low-level private/public keypair operation

PKey object of this module is wrapper around OpenSSL EVP_PKEY object.
"""

from ctypes import c_char_p, c_char, c_void_p, c_int, c_long, POINTER
from ctypes import create_string_buffer, byref, memmove, CFUNCTYPE
from ctypescrypto import libcrypto

from ctypescrypto.exception import LibCryptoError, clear_err_stack
from ctypescrypto.bio import Membio

__all__ = ['PKeyError', 'password_callback', 'PKey', 'PW_CALLBACK_FUNC']


PW_CALLBACK_FUNC = CFUNCTYPE(c_int, POINTER(c_char), c_int, c_int, c_char_p)
""" Function type for pem password callback """


class PKeyError(LibCryptoError):
    """ Exception thrown if libcrypto finctions return an error """
    pass


class _PasswordCallbackHelper(object):
    """
    Tool class for represent user defined password callback function as CFUNCTYPE function
    """
    def __init__(self, format="PEM", callback=None):
        if format != "PEM" and callback is not None:
            raise TypeError("Only PEM key format supports encryption")
        self._callback = callback

    @property
    def callback(self):
        return self._pw_callback(self._callback)

    @staticmethod
    def _pw_callback(callback_func):
        def c_callback(buf, length, rwflag, userdata):
            res = callback_func(length, rwflag, userdata) if callback_func else userdata
            cnt = min(length, len(res))
            memmove(buf, res, cnt)
            return cnt
        return PW_CALLBACK_FUNC(c_callback)


class PKey(object):
    """
    Represents public/private key pair. Wrapper around EVP_PKEY
    libcrypto object.

    May contain either both private and public key (such objects can be
    used for signing, deriving shared key as well as verifying or public
    key only, which can be used for verifying or as peer key when
    deriving.

    @var cansign is true key has private part.
    @var key contain pointer to EVP_PKEY and should be passed to various
         libcrypto routines
    """
    def __init__(self, ptr=None, privkey=None, pubkey=None, format="PEM",
                 cansign=False, password=None, callback=None):
        helper = _PasswordCallbackHelper(format, callback)
        if not ptr is None:
            self.key = ptr
            self.cansign = cansign
            if not privkey is None or not pubkey is None:
                raise TypeError("Just one of ptr, pubkey or privkey can " +
                                "be specified")
        elif not privkey is None:
            if not pubkey is None:
                raise TypeError("Just one of ptr, pubkey or privkey can " +
                                "be specified")
            bio = Membio(privkey)
            self.cansign = True
            if format == "PEM":
                self.key = libcrypto.PEM_read_bio_PrivateKey(bio.bio, None,
                                                             helper.callback,
                                                             c_char_p(password))
            else:
                self.key = libcrypto.d2i_PrivateKey_bio(bio.bio, None)
            if self.key is None:
                raise PKeyError("error parsing private key")
        elif not pubkey is None:
            bio = Membio(pubkey)
            self.cansign = False
            if format == "PEM":
                self.key = libcrypto.PEM_read_bio_PUBKEY(bio.bio, None,
                                                         helper.callback,
                                                         c_char_p(password))
            else:
                self.key = libcrypto.d2i_PUBKEY_bio(bio.bio, None)
            if self.key is None:
                raise PKeyError("error parsing public key")
        else:
            raise TypeError("Neither public, nor private key is specified")


    def __del__(self):
        """ Frees EVP_PKEY object (note, it is reference counted) """
        libcrypto.EVP_PKEY_free(self.key)

    def __eq__(self, other):
        """ Compares two public keys. If one has private key and other
            doesn't it doesn't affect result of comparation
        """
        return libcrypto.EVP_PKEY_cmp(self.key, other.key) == 1

    def __ne__(self, other):
        """ Compares two public key for not-equality """
        return not self.__eq__(other)

    def __str__(self):
        """ printable representation of public key """
        bio = Membio()
        libcrypto.EVP_PKEY_print_public(bio.bio, self.key, 0, None)
        return str(bio)

    def sign(self, digest, **kwargs):
        """
        Signs given digest and retirns signature
        Keyword arguments allows to set various algorithm-specific
        parameters. See pkeyutl(1) manual.
        """
        ctx = libcrypto.EVP_PKEY_CTX_new(self.key, None)
        if ctx is None:
            raise PKeyError("Initailizing sign context")
        if libcrypto.EVP_PKEY_sign_init(ctx) < 1:
            raise PKeyError("sign_init")
        self._configure_context(ctx, kwargs)
        # Find out signature size
        siglen = c_long(0)
        if libcrypto.EVP_PKEY_sign(ctx, None, byref(siglen), digest,
                                   len(digest)) < 1:
            raise PKeyError("computing signature length")
        sig = create_string_buffer(siglen.value)
        if libcrypto.EVP_PKEY_sign(ctx, sig, byref(siglen), digest,
                                   len(digest)) < 1:
            raise PKeyError("signing")
        libcrypto.EVP_PKEY_CTX_free(ctx)
        return sig.raw[:int(siglen.value)]

    def verify(self, digest, signature, **kwargs):
        """
        Verifies given signature on given digest
        Returns True if Ok, False if don't match
        Keyword arguments allows to set algorithm-specific
        parameters
        """
        ctx = libcrypto.EVP_PKEY_CTX_new(self.key, None)
        if ctx is None:
            raise PKeyError("Initailizing verify context")
        if libcrypto.EVP_PKEY_verify_init(ctx) < 1:
            raise PKeyError("verify_init")
        self._configure_context(ctx, kwargs)
        ret = libcrypto.EVP_PKEY_verify(ctx, signature, len(signature), digest,
                                        len(digest))
        if ret < 0:
            raise PKeyError("Signature verification")
        libcrypto.EVP_PKEY_CTX_free(ctx)
        return ret > 0

    def derive(self, peerkey, **kwargs):
        """
        Derives shared key (DH,ECDH,VKO 34.10). Requires
        private key available

        @param peerkey - other key (may be public only)

        Keyword parameters are algorithm-specific
        """
        if not self.cansign:
            raise ValueError("No private key available")
        ctx = libcrypto.EVP_PKEY_CTX_new(self.key, None)
        if ctx is None:
            raise PKeyError("Initailizing derive context")
        if libcrypto.EVP_PKEY_derive_init(ctx) < 1:
            raise PKeyError("derive_init")

        # This is workaround around missing functionality in GOST engine
        # it provides only numeric control command to set UKM, not
        # string one.
        self._configure_context(ctx, kwargs, ["ukm"])
        if libcrypto.EVP_PKEY_derive_set_peer(ctx, peerkey.key) <= 0:
            raise PKeyError("Cannot set peer key")
        if "ukm" in kwargs:
            # We just hardcode numeric command to set UKM here
            if libcrypto.EVP_PKEY_CTX_ctrl(ctx, -1, 1 << 10, 8, 8,
                                           kwargs["ukm"]) <= 0:
                raise PKeyError("Cannot set UKM")
        keylen = c_long(0)
        if libcrypto.EVP_PKEY_derive(ctx, None, byref(keylen)) <= 0:
            raise PKeyError("computing shared key length")
        buf = create_string_buffer(keylen.value)
        if libcrypto.EVP_PKEY_derive(ctx, buf, byref(keylen)) <= 0:
            raise PKeyError("computing actual shared key")
        libcrypto.EVP_PKEY_CTX_free(ctx)
        return buf.raw[:int(keylen.value)]

    @staticmethod
    def generate(algorithm, **kwargs):
        """
        Generates new private-public key pair for given algorithm
        (string like 'rsa','ec','gost2001') and algorithm-specific
        parameters.

        Algorithm specific paramteers for RSA:

        rsa_keygen_bits=number - size of key to be generated
        rsa_keygen_pubexp - RSA public expontent(default 65537)

        Algorithm specific parameters for DSA,DH and EC

        paramsfrom=PKey object

        copy parameters of newly generated key from existing key

        Algorithm specific parameters for GOST2001

        paramset= paramset name where name is one of
        'A','B','C','XA','XB','test'

        paramsfrom does work too
        """
        tmpeng = c_void_p(None)
        ameth = libcrypto.EVP_PKEY_asn1_find_str(byref(tmpeng), algorithm, -1)
        if ameth is None:
            raise PKeyError("Algorithm %s not foind\n"%(algorithm))
        clear_err_stack()
        pkey_id = c_int(0)
        libcrypto.EVP_PKEY_asn1_get0_info(byref(pkey_id), None, None, None,
                                          None, ameth)
        #libcrypto.ENGINE_finish(tmpeng)
        if "paramsfrom" in kwargs:
            ctx = libcrypto.EVP_PKEY_CTX_new(kwargs["paramsfrom"].key, None)
        else:
            ctx = libcrypto.EVP_PKEY_CTX_new_id(pkey_id, None)
        # FIXME support EC curve as keyword param by invoking paramgen
        # operation
        if ctx is None:
            raise PKeyError("Creating context for key type %d"%(pkey_id.value))
        if libcrypto.EVP_PKEY_keygen_init(ctx) <= 0:
            raise PKeyError("keygen_init")
        PKey._configure_context(ctx, kwargs, ["paramsfrom"])
        key = c_void_p(None)
        if libcrypto.EVP_PKEY_keygen(ctx, byref(key)) <= 0:
            raise PKeyError("Error generating key")
        libcrypto.EVP_PKEY_CTX_free(ctx)
        return PKey(ptr=key, cansign=True)

    def exportpub(self, format="PEM"):
        """
        Returns public key as PEM or DER structure.
        """
        bio = Membio()
        if format == "PEM":
            retcode = libcrypto.PEM_write_bio_PUBKEY(bio.bio, self.key)
        else:
            retcode = libcrypto.i2d_PUBKEY_bio(bio.bio, self.key)
        if retcode == 0:
            raise PKeyError("error serializing public key")
        return str(bio)

    def exportpriv(self, format="PEM", password=None, cipher=None,
                   callback=None):
        """
        Returns private key as PEM or DER Structure.
        If password and cipher are specified, encrypts key
        on given password, using given algorithm. Cipher must be
        an ctypescrypto.cipher.CipherType object
        """
        bio = Membio()
        helper = _PasswordCallbackHelper(format, callback)

        if cipher is None:
            evp_cipher = None
        else:
            evp_cipher = cipher.cipher
        if format == "PEM":
            ret = libcrypto.PEM_write_bio_PrivateKey(bio.bio, self.key,
                                                     evp_cipher, None, 0,
                                                     helper.callback,
                                                     c_char_p(password))
        else:
            ret = libcrypto.i2d_PKCS8PrivateKey_bio(bio.bio, self.key,
                                                    evp_cipher, None, 0,
                                                    helper.callback,
                                                    c_char_p(password))
        if ret == 0:
            raise PKeyError("error serializing private key")
        return str(bio)

    @staticmethod
    def _configure_context(ctx, opts, skip=()):
        """
        Configures context of public key operations
        @param ctx - context to configure
        @param opts - dictionary of options (from kwargs of calling
            function)
        @param skip - list of options which shouldn't be passed to
            context
        """

        for oper in opts:
            if oper in skip:
                continue
            ret = libcrypto.EVP_PKEY_CTX_ctrl_str(ctx, oper, str(opts[oper]))
            if ret == -2:
                raise PKeyError("Parameter %s is not supported by key" % oper)
            if ret < 1:
                raise PKeyError("Error setting parameter %s" % oper)
# Declare function prototypes
libcrypto.EVP_PKEY_cmp.argtypes = (c_void_p, c_void_p)
libcrypto.PEM_read_bio_PrivateKey.restype = c_void_p
libcrypto.PEM_read_bio_PrivateKey.argtypes = (c_void_p, POINTER(c_void_p),
                                              PW_CALLBACK_FUNC, c_char_p)
libcrypto.PEM_read_bio_PUBKEY.restype = c_void_p
libcrypto.PEM_read_bio_PUBKEY.argtypes = (c_void_p, POINTER(c_void_p),
                                          PW_CALLBACK_FUNC, c_char_p)
libcrypto.d2i_PUBKEY_bio.restype = c_void_p
libcrypto.d2i_PUBKEY_bio.argtypes = (c_void_p, c_void_p)
libcrypto.d2i_PrivateKey_bio.restype = c_void_p
libcrypto.d2i_PrivateKey_bio.argtypes = (c_void_p, c_void_p)
libcrypto.EVP_PKEY_print_public.argtypes = (c_void_p, c_void_p, c_int, c_void_p)
libcrypto.EVP_PKEY_asn1_find_str.restype = c_void_p
libcrypto.EVP_PKEY_asn1_find_str.argtypes = (c_void_p, c_char_p, c_int)
libcrypto.EVP_PKEY_asn1_get0_info.restype = c_int
libcrypto.EVP_PKEY_asn1_get0_info.argtypes = (POINTER(c_int), POINTER(c_int),
                                              POINTER(c_int), POINTER(c_char_p),
                                              POINTER(c_char_p), c_void_p)
libcrypto.EVP_PKEY_cmp.restype = c_int
libcrypto.EVP_PKEY_cmp.argtypes = (c_void_p, c_void_p)
libcrypto.EVP_PKEY_CTX_ctrl_str.restype = c_int
libcrypto.EVP_PKEY_CTX_ctrl_str.argtypes = (c_void_p, c_void_p, c_void_p)
libcrypto.EVP_PKEY_CTX_ctrl.restype = c_int
libcrypto.EVP_PKEY_CTX_ctrl.argtypes = (c_void_p, c_int, c_int, c_int, c_int,
                                        c_void_p)
libcrypto.EVP_PKEY_CTX_free.argtypes = (c_void_p, )
libcrypto.EVP_PKEY_CTX_new.restype = c_void_p
libcrypto.EVP_PKEY_CTX_new.argtypes = (c_void_p, c_void_p)
libcrypto.EVP_PKEY_CTX_new_id.restype = c_void_p
libcrypto.EVP_PKEY_CTX_new_id.argtypes = (c_int, c_void_p)
libcrypto.EVP_PKEY_derive.restype = c_int
libcrypto.EVP_PKEY_derive.argtypes = (c_void_p, c_char_p, POINTER(c_long))
libcrypto.EVP_PKEY_derive_init.restype = c_int
libcrypto.EVP_PKEY_derive_init.argtypes = (c_void_p, )
libcrypto.EVP_PKEY_derive_set_peer.restype = c_int
libcrypto.EVP_PKEY_derive_set_peer.argtypes = (c_void_p, c_void_p)
libcrypto.EVP_PKEY_free.argtypes = (c_void_p,)
libcrypto.EVP_PKEY_keygen.restype = c_int
libcrypto.EVP_PKEY_keygen.argtypes = (c_void_p, c_void_p)
libcrypto.EVP_PKEY_keygen_init.restype = c_int
libcrypto.EVP_PKEY_keygen_init.argtypes = (c_void_p, )
libcrypto.EVP_PKEY_sign.restype = c_int
libcrypto.EVP_PKEY_sign.argtypes = (c_void_p, c_char_p, POINTER(c_long),
                                    c_char_p, c_long)
libcrypto.EVP_PKEY_sign_init.restype = c_int
libcrypto.EVP_PKEY_sign_init.argtypes = (c_void_p, )
libcrypto.EVP_PKEY_verify.restype = c_int
libcrypto.EVP_PKEY_verify.argtypes = (c_void_p, c_char_p, c_long, c_char_p,
                                      c_long)
libcrypto.EVP_PKEY_verify_init.restype = c_int
libcrypto.EVP_PKEY_verify_init.argtypes = (c_void_p, )
libcrypto.PEM_write_bio_PrivateKey.argtypes = (c_void_p, c_void_p, c_void_p,
                                               c_char_p, c_int,
                                               PW_CALLBACK_FUNC, c_char_p)
libcrypto.PEM_write_bio_PUBKEY.argtypes = (c_void_p, c_void_p)
libcrypto.i2d_PUBKEY_bio.argtypes = (c_void_p, c_void_p)
libcrypto.i2d_PKCS8PrivateKey_bio.argtypes = (c_void_p, c_void_p, c_void_p,
                                              c_char_p, c_int,
                                              PW_CALLBACK_FUNC, c_char_p)
libcrypto.ENGINE_finish.argtypes = (c_void_p, )
