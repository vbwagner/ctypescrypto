"""
    Interface to some libcrypto functions

"""


from ctypes import CDLL, c_char_p
from ctypes.util import find_library

def config(filename=None):
    """
        Loads OpenSSL Config file. If none are specified, loads default
        (compiled in) one
    """
    libcrypto.OPENSSL_config(filename)

__all__ = ['config']

libcrypto = CDLL(find_library("libcrypto"))
libcrypto.OPENSSL_config.argtypes = (c_char_p, )
libcrypto.OPENSSL_add_all_algorithms_conf()
