"""
	Interface to some libcrypto functions

"""

from ctypes import CDLL

libcrypto = CDLL("libcrypto.so.1.0.0")
libcrypto.OPENSSL_config(None)
