"""
Implements interface to OpenSSL EVP_Digest* functions.

Interface  made as close to hashlib as possible.

This module is really an excess effort. Hashlib allows access to
mostly same functionality except oids and nids of hashing
algortithms (which might be needed for private key operations).

hashlib even allows to use engine-provided digests if it is build
with dinamically linked libcrypto - so use
ctypescrypto.engine.set_default("gost",xFFFF) and md_gost94
algorithm would be available both to this module and hashlib.

"""
from ctypes import c_int, c_char_p, c_void_p, POINTER, c_long, c_longlong
from ctypes import create_string_buffer, byref
from ctypescrypto import libcrypto,pyver, bintype
from ctypescrypto.exception import LibCryptoError
from ctypescrypto.oid import Oid
DIGEST_ALGORITHMS = ("MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512")

__all__ = ['DigestError', 'Digest', 'DigestType', 'new']

class DigestError(LibCryptoError):
    """ Exception raised if some OpenSSL function returns error """
    pass

def new(algname):
    """
    Behaves just like hashlib.new. Creates digest object by
    algorithm name
    """

    digest_type = DigestType(algname)
    return Digest(digest_type)

class DigestType(object):
    """
    Represents EVP_MD object - constant structure which describes
    digest algorithm
    """
    def __init__(self, digest_name):
        """
        Finds digest by its name. You can pass Oid object instead of
        name.

        Special case is when None is passed as name. In this case
        unitialized digest is created, and can be initalized later
        by setting its digest attribute to pointer to EVP_MD
        """
        if digest_name is None:
            return

        if isinstance(digest_name, Oid):
            self.digest_name = digest_name.longname()
        else:
            self.digest_name = str(digest_name)
        self.digest = libcrypto.EVP_get_digestbyname(self.digest_name.encode('us-ascii'))
        if self.digest is None:
            raise DigestError("Unknown digest: %s" % self.digest_name)

    @property
    def name(self):
        """ Returns name of the digest """
        if not hasattr(self, 'digest_name'):
            self.digest_name = Oid(libcrypto.EVP_MD_type(self.digest)
                                  ).longname()
        return self.digest_name

    def __del__(self):
        """ Empty destructor for constant object """
        pass

    @property
    def digest_size(self):
        """ Returns size of digest """
        return libcrypto.EVP_MD_size(self.digest)

    @property
    def block_size(self):
        """ Returns block size of the digest """
        return libcrypto.EVP_MD_block_size(self.digest)

    @property
    def oid(self):
        """ Returns Oid object of digest type """
        return Oid(libcrypto.EVP_MD_type(self.digest))

class Digest(object):
    """
    Represents EVP_MD_CTX object which actually used to calculate
    digests.
    """

    def __init__(self, digest_type):
        """
        Initializes digest using given type.
        """
        self.ctx = self.newctx()
        if self.ctx is None:
            raise DigestError("Unable to create digest context")
        self.digest_out = None
        self.digest_finalized = False
        result = libcrypto.EVP_DigestInit_ex(self.ctx, digest_type.digest, None)
        if result == 0:
            self._clean_ctx()
            raise DigestError("Unable to initialize digest")
        self.digest_type = digest_type
        self.digest_size = self.digest_type.digest_size
        self.block_size = self.digest_type.block_size

    def __del__(self):
        """ Uses _clean_ctx internal method """
        self._clean_ctx()

    def update(self, data, length=None):
        """
        Hashes given byte string

        @param data - string to hash
        @param length - if not specifed, entire string is hashed,
                otherwise only first length bytes
        """
        if self.digest_finalized:
            raise DigestError("No updates allowed")
        if not isinstance(data, bintype):
            raise TypeError("A byte string is expected")
        if length is None:
            length = len(data)
        elif length > len(data):
            raise ValueError("Specified length is greater than length of data")
        result = libcrypto.EVP_DigestUpdate(self.ctx, c_char_p(data), length)
        if result != 1:
            raise DigestError("Unable to update digest")

    def digest(self, data=None):
        """
        Finalizes digest operation and return digest value
        Optionally hashes more data before finalizing
        """
        if self.digest_finalized:
            return self.digest_out.raw[:self.digest_size]
        if data is not None:
            self.update(data)
        self.digest_out = create_string_buffer(256)
        length = c_long(0)
        result = libcrypto.EVP_DigestFinal_ex(self.ctx, self.digest_out,
                                              byref(length))
        if result != 1:
            raise DigestError("Unable to finalize digest")
        self.digest_finalized = True
        return self.digest_out.raw[:self.digest_size]
    def copy(self):
        """
        Creates copy of the digest CTX to allow to compute digest
        while being able to hash more data
        """

        new_digest = Digest(self.digest_type)
        libcrypto.EVP_MD_CTX_copy(new_digest.ctx, self.ctx)
        return new_digest

    def _clean_ctx(self):
        """
        Clears and deallocates context
        """
        try:
            if self.ctx is not None:
                libcrypto.EVP_MD_CTX_free(self.ctx)
                del self.ctx
        except AttributeError:
            pass
        self.digest_out = None
        self.digest_finalized = False

    def hexdigest(self, data=None):
        """
            Returns digest in the hexadecimal form. For compatibility
            with hashlib
        """
        from base64 import b16encode
        if pyver == 2:
            return b16encode(self.digest(data))
        else:
            return b16encode(self.digest(data)).decode('us-ascii')


# Declare function result and argument types
libcrypto.EVP_get_digestbyname.restype = c_void_p
libcrypto.EVP_get_digestbyname.argtypes = (c_char_p, )
# These two functions are renamed in OpenSSL 1.1.0
if hasattr(libcrypto,"EVP_MD_CTX_create"):
    Digest.newctx = libcrypto.EVP_MD_CTX_create
    Digest.freectx = libcrypto.EVP_MD_CTX_destroy
else:
    Digest.newctx = libcrypto.EVP_MD_CTX_new
    Digest.freectx = libcrypto.EVP_MD_CTX_free
Digest.newctx.restype = c_void_p
Digest.freectx.argtypes = (c_void_p, )
# libcrypto.EVP_MD_CTX_create has no arguments
libcrypto.EVP_DigestInit_ex.restype = c_int
libcrypto.EVP_DigestInit_ex.argtypes = (c_void_p, c_void_p, c_void_p)
libcrypto.EVP_DigestUpdate.restype = c_int
libcrypto.EVP_DigestUpdate.argtypes = (c_void_p, c_char_p, c_longlong)
libcrypto.EVP_DigestFinal_ex.restype = c_int
libcrypto.EVP_DigestFinal_ex.argtypes = (c_void_p, c_char_p, POINTER(c_long))
libcrypto.EVP_MD_CTX_copy.restype = c_int
libcrypto.EVP_MD_CTX_copy.argtypes = (c_void_p, c_void_p)
libcrypto.EVP_MD_type.argtypes = (c_void_p, )
libcrypto.EVP_MD_size.argtypes = (c_void_p, )
libcrypto.EVP_MD_block_size.restype = c_int
libcrypto.EVP_MD_block_size.argtypes = (c_void_p, )
libcrypto.EVP_MD_size.restype = c_int
libcrypto.EVP_MD_size.argtypes = (c_void_p, )
libcrypto.EVP_MD_type.restype = c_int
libcrypto.EVP_MD_type.argtypes = (c_void_p, )
