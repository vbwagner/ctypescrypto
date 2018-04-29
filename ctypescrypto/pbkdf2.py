"""
PKCS5 PBKDF2 function.

"""

from ctypes import c_char_p, c_int, c_void_p, create_string_buffer
from ctypescrypto import libcrypto, chartype
from ctypescrypto.digest import DigestType
from ctypescrypto.exception import LibCryptoError

__all__ = ['pbkdf2']

def pbkdf2(password, salt, outlen, digesttype="sha1", iterations=2000):
    """
    Interface to PKCS5_PBKDF2_HMAC function
    Parameters:

    @param password - password to derive key from
    @param salt - random salt to use for key derivation
    @param outlen - number of bytes to derive
    @param digesttype - name of digest to use to use (default sha1)
    @param iterations - number of iterations to use

    @returns outlen bytes of key material derived from password and salt
    """
    dgst = DigestType(digesttype)
    out = create_string_buffer(outlen)
    if isinstance(password,chartype):
        pwd = password.encode("utf-8")
    else:
        pwd = password
    res = libcrypto.PKCS5_PBKDF2_HMAC(pwd, len(pwd), salt, len(salt),
                                      iterations, dgst.digest, outlen, out)
    if res <= 0:
        raise LibCryptoError("error computing PBKDF2")
    return out.raw

libcrypto.PKCS5_PBKDF2_HMAC.argtypes = (c_char_p, c_int, c_char_p, c_int, c_int,
                                        c_void_p, c_int, c_char_p)
libcrypto.PKCS5_PBKDF2_HMAC.restupe = c_int
