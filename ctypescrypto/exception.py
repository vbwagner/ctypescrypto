"""
Exception which extracts libcrypto error information
"""
from ctypes import *
from ctypescrypto import libcrypto
strings_loaded=False

__all__ = ['LibCryptoError','clear_err_stack']

def _check_null(s):
	"""
	Handle transparently NULL returned from error reporting functions
	instead of strings
	"""
	if s is None:	
		return ""
	return s

class LibCryptoError(Exception):
	"""
		Exception for libcrypto errors. Adds all the info, which can be
		extracted from internal (per-thread) libcrypto error stack to the message,
		passed to the constructor.
	"""
	def __init__(self,msg):
		global strings_loaded
		if not strings_loaded:
			libcrypto.ERR_load_crypto_strings()
			strings_loaded = True
		e=libcrypto.ERR_get_error()
		m = msg
		while e != 0:
			m+="\n\t"+_check_null(libcrypto.ERR_lib_error_string(e))+":"+\
			  _check_null(libcrypto.ERR_func_error_string(e))+":"+\
			  _check_null(libcrypto.ERR_reason_error_string(e))
			e=libcrypto.ERR_get_error()
		self.args=(m,)

def clear_err_stack():
	"""
	  Clears internal libcrypto err stack. Call it if you've checked
	  return code and processed exceptional situation, so subsequent
	  raising of the LibCryptoError wouldn't list already handled errors
	"""
	libcrypto.ERR_clear_error()


libcrypto.ERR_lib_error_string.restype=c_char_p
libcrypto.ERR_func_error_string.restype=c_char_p
libcrypto.ERR_reason_error_string.restype=c_char_p
