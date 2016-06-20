"""
    Interface to some libcrypto functions

"""


from ctypes import CDLL, c_char_p
from ctypes.util import find_library
import sys

def config(filename=None):
    """
        Loads OpenSSL Config file. If none are specified, loads default
        (compiled in) one
    """
    libcrypto.OPENSSL_config(filename)

__all__ = ['config']

if sys.platform.startswith('win'):
    __libname__ = find_library('libeay32')
else:
    __libname__ = find_library('crypto')

if __libname__ is None:
    raise OSError("Cannot find OpenSSL crypto library")

#__libname__ = "/usr/local/ssl/lib/libcrypto.so.1.1"

libcrypto = CDLL(__libname__)
libcrypto.OPENSSL_config.argtypes = (c_char_p, )
libcrypto.OPENSSL_add_all_algorithms_conf()
