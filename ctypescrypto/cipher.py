"""
access to symmetric ciphers from libcrypto

"""
from ctypes import create_string_buffer, c_char_p, c_void_p, c_int
from ctypes import byref, POINTER
from ctypescrypto import libcrypto, pyver, bintype
from ctypescrypto.exception import LibCryptoError
from ctypescrypto.oid import Oid

CIPHER_ALGORITHMS = ("DES", "DES-EDE3", "BF", "AES-128", "AES-192", "AES-256")
CIPHER_MODES = ("STREAM", "ECB", "CBC", "CFB", "OFB", "CTR", "GCM")

#

__all__ = ['CipherError', 'new', 'Cipher', 'CipherType']

class CipherError(LibCryptoError):
    """
    Exception raise when OpenSSL function returns error
    """
    pass

def new(algname, key, encrypt=True, iv=None):
    """
    Returns new cipher object ready to encrypt-decrypt data

    @param algname - string algorithm name like in opemssl command
                     line
    @param key - binary string representing ciher key
    @param encrypt - if True (default) cipher would be initialized
                    for encryption, otherwise - for decrypton
    @param iv - initialization vector
    """
    ciph_type = CipherType(algname)
    return Cipher(ciph_type, key, iv, encrypt)

class CipherType(object):
    """
    Describes cihper algorihm. Can be used to produce cipher
    instance and to get various information about cihper
    """

    def __init__(self, cipher_name):
        """
        Constructs cipher algortihm using textual name as in openssl
        command line
        """
        if pyver > 2:
            cipher_name = cipher_name.encode('utf-8')
        self.cipher = libcrypto.EVP_get_cipherbyname(cipher_name)
        if self.cipher is None:
            raise CipherError("Unknown cipher: %s" % cipher_name)

    def __del__(self):
        """
        It is constant object with do-nothing del
        """
        pass

    def block_size(self):
        """
        Returns block size of the cipher
        """
        return libcrypto.EVP_CIPHER_block_size(self.cipher)

    def key_length(self):
        """
        Returns key length of the cipher
        """
        return libcrypto.EVP_CIPHER_key_length(self.cipher)

    def iv_length(self):
        """
        Returns initialization vector length of the cipher
        """
        return libcrypto.EVP_CIPHER_iv_length(self.cipher)

    def flags(self):
        """
        Return cipher flags. Low three bits of the flags encode
        cipher mode (see mode). Higher bits  is combinatuon of
        EVP_CIPH* constants defined in the <openssl/evp.h>
        """
        return libcrypto.EVP_CIPHER_flags(self.cipher)

    def mode(self):
        """
        Returns cipher mode as string constant like CBC, OFB etc.
        """
        return CIPHER_MODES[self.flags() & 0x7]

    def algo(self):
        """
        Return cipher's algorithm name, derived from OID
        """
        return self.oid().shortname()

    def oid(self):
        """
        Returns ASN.1 object identifier of the cipher as
        ctypescrypto.oid.Oid object
        """
        return Oid(libcrypto.EVP_CIPHER_nid(self.cipher))

class Cipher(object):
    """
    Performs actual encrypton decryption
    Note that object keeps some internal state.
    To obtain full ciphertext (or plaintext during decihpering)
    user should concatenate results of all calls of update with
    result of finish
    """
    def __init__(self, cipher_type, key, iv, encrypt=True):
        """
        Initializing cipher instance.

        @param cipher_type - CipherType object
        @param key = binary string representing the key
        @param iv - binary string representing initializtion vector
        @param encrypt - if True(default) we ere encrypting.
               Otherwise decrypting

        """
        self._clean_ctx()
        # Check key and iv length
        if key is None:
            raise ValueError("No key specified")

        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)
        self.ctx = libcrypto.EVP_CIPHER_CTX_new()
        if self.ctx == 0:
            raise CipherError("Unable to create cipher context")
        self.encrypt = encrypt
        enc = 1 if encrypt else 0
        if not iv is None and len(iv) != cipher_type.iv_length():
            raise ValueError("Invalid IV length for this algorithm")

        if len(key) != cipher_type.key_length():
            if (cipher_type.flags() & 8) != 0:
                # Variable key length cipher.
                result = libcrypto.EVP_CipherInit_ex(self.ctx,
                                                     cipher_type.cipher,
                                                     None, None, None,
                                                     c_int(enc))
                result = libcrypto.EVP_CIPHER_CTX_set_key_length(self.ctx,
                                                                 len(key))
                if result == 0:
                    self._clean_ctx()
                    raise CipherError("Unable to set key length")
                result = libcrypto.EVP_CipherInit_ex(self.ctx, None, None,
                                                     key_ptr, iv_ptr,
                                                     c_int(enc))
            else:
                raise ValueError("Invalid key length for this algorithm")
        else:
            result = libcrypto.EVP_CipherInit_ex(self.ctx, cipher_type.cipher,
                                                 None, key_ptr, iv_ptr,
                                                 c_int(enc))
        if result == 0:
            self._clean_ctx()
            raise CipherError("Unable to initialize cipher")
        self.cipher_type = cipher_type
        self.block_size = self.cipher_type.block_size()
        self.cipher_finalized = False

    def __del__(self):
        """
        We define _clean_ctx() to do all the cleanup
        """
        self._clean_ctx()

    def padding(self, padding=True):
        """
        Sets padding mode of the cipher
        """
        padding_flag = 1 if padding else 0
        libcrypto.EVP_CIPHER_CTX_set_padding(self.ctx, padding_flag)

    def update(self, data):
        """
        Performs actual encrypton/decrypion

        @param data - part of the plain text/ciphertext to process
        @returns - part of ciphercext/plain text

        Passed chunk of text doesn't need to contain full ciher
        blocks. If neccessery, part of passed data would be kept
        internally until next data would be received or finish
        called
        """
        if self.cipher_finalized:
            raise CipherError("No updates allowed")
        if not isinstance(data, bintype):
            raise TypeError("A byte string is expected")
        if len(data) == 0:
            return ""
        outbuf = create_string_buffer(self.block_size+len(data))
        outlen = c_int(0)
        ret = libcrypto.EVP_CipherUpdate(self.ctx, outbuf, byref(outlen),
                                         data, len(data))
        if ret <= 0:
            self._clean_ctx()
            self.cipher_finalized = True
            raise CipherError("problem processing data")
        return outbuf.raw[:int(outlen.value)]

    def finish(self):
        """
        Finalizes processing. If some data are kept in the internal
        state, they would be processed and returned.
        """
        if self.cipher_finalized:
            raise CipherError("Cipher operation is already completed")
        outbuf = create_string_buffer(self.block_size)
        self.cipher_finalized = True
        outlen = c_int(0)
        result = libcrypto.EVP_CipherFinal_ex(self.ctx, outbuf, byref(outlen))
        if result == 0:
            self._clean_ctx()
            raise CipherError("Unable to finalize cipher")
        if outlen.value > 0:
            return outbuf.raw[:int(outlen.value)]
        else:
            return b""

    def _clean_ctx(self):
        """
        Cleans up cipher ctx and deallocates it
        """
        try:
            if self.ctx is not None:
                self.__ctxcleanup(self.ctx)
                libcrypto.EVP_CIPHER_CTX_free(self.ctx)
                del self.ctx
        except AttributeError:
            pass
        self.cipher_finalized = True


#
# Used C function block_size
#
libcrypto.EVP_CIPHER_block_size.argtypes = (c_void_p, )

#Function EVP_CIPHER_CTX_cleanup renamed to EVP_CIPHER_CTX_reset
# in the OpenSSL 1.1.0
if hasattr(libcrypto,"EVP_CIPHER_CTX_cleanup"):
    Cipher.__ctxcleanup = libcrypto.EVP_CIPHER_CTX_cleanup 
else:
    Cipher.__ctxcleanup = libcrypto.EVP_CIPHER_CTX_reset
Cipher.__ctxcleanup.argtypes  = (c_void_p, )
libcrypto.EVP_CIPHER_CTX_free.argtypes = (c_void_p, )
libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p
libcrypto.EVP_CIPHER_CTX_set_padding.argtypes = (c_void_p, c_int)
libcrypto.EVP_CipherFinal_ex.argtypes = (c_void_p, c_char_p, POINTER(c_int))
libcrypto.EVP_CIPHER_flags.argtypes = (c_void_p, )
libcrypto.EVP_CipherInit_ex.argtypes = (c_void_p, c_void_p, c_void_p, c_char_p,
                                        c_char_p, c_int)
libcrypto.EVP_CIPHER_iv_length.argtypes = (c_void_p, )
libcrypto.EVP_CIPHER_key_length.argtypes = (c_void_p, )
libcrypto.EVP_CIPHER_nid.argtypes = (c_void_p, )
libcrypto.EVP_CipherUpdate.argtypes = (c_void_p, c_char_p, POINTER(c_int),
                                       c_char_p, c_int)
libcrypto.EVP_get_cipherbyname.restype = c_void_p
libcrypto.EVP_get_cipherbyname.argtypes = (c_char_p, )
libcrypto.EVP_CIPHER_CTX_set_key_length.argtypes = (c_void_p, c_int)
