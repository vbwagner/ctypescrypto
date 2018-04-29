"""
    Interface to some libcrypto functions

"""


from ctypes import CDLL, c_char_p, c_void_p, c_long,c_uint64
from ctypes.util import find_library
import sys
global strings_loaded

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
pyver=int(sys.version[0])
if pyver == 2:
    bintype = str
    chartype = unicode
    inttype = (int, long)
else:
    bintype = bytes
    chartype = str
    inttype = int

if hasattr(libcrypto,'OPENSSL_init_crypto'):
    libcrypto.OPENSSL_init_crypto.argtypes = (c_uint64,c_void_p)
    libcrypto.OPENSSL_init_crypto(2+4+8+0x40,None)
    strings_loaded = True
else:     
    libcrypto.OPENSSL_add_all_algorithms_conf()
    strings_loaded = False
