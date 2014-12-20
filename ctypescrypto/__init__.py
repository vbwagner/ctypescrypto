"""
	Interface to some libcrypto functions

"""


from ctypes import CDLL,c_char_p

def config(filename=None):
	"""
		Loads OpenSSL Config file. If none are specified, loads default
		(compiled in) one
	"""
	libcrypto.OPENSSL_config(filename)

__all__ = ['bio','cipher','cms','config','digest','ec','engine','exception','oid','pbkdf2','pkey','rand','x509']

libcrypto = CDLL("libcrypto.so.1.0.0")
libcrypto.OPENSSL_config.argtypes=(c_char_p,)
libcrypto.OPENSSL_add_all_algorithms_conf()
