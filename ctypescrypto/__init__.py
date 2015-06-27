"""
    Interface to some libcrypto functions

"""


from ctypes import CDLL, c_char_p

def config(filename=None):
    """
        Loads OpenSSL Config file. If none are specified, loads default
        (compiled in) one
    """
    libcrypto.OPENSSL_config(filename)

__all__ = ['config']

libcrypto = CDLL("libcrypto.so.1.0.0")
libcrypto.OPENSSL_config.argtypes = (c_char_p, )
libcrypto.OPENSSL_add_all_algorithms_conf()
