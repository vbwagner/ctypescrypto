from ctypescrypto import libcrypto
from ctypes import c_char_p, c_int, string_at
class Membio:
	""" 
		Provides interface to OpenSSL memory bios 
		use str() to get contents of writable bio
		use bio member to pass to libcrypto function
	"""
	def __init__(self,data=None):
		""" If data is specified, creates read-only BIO. If data is
			None, creates writable BIO
		"""
		if data is None:
			method=libcrypto.BIO_s_mem()
			self.bio=libcrypto.BIO_new(method)
		else:
			self.bio=libcrypto.BIO_new_mem_buf(c_char_p(data),len(data))q
	def __del__(self):
		libcrypto.BIO_free(self.bio)
		del(self.bio)
	def __str__(self):
		p=c_char_p(None)
		l=BIO_get_mem_data(self.bio,byref(p))
		return string_at(p,l)
#FIXME TODO - BIO should have stream-like interface
libcrypto.BIO_s_mem.restype=c_void_p
libcrypto.BIO_new.restype=c_void_p
libcrypto.BIO_new.argtypes=(c_void_p,)
libcrypto.BIO_get_mem_data.restype=c_long
libcrypto.BIO_get_mem_data.argtypes=(c_void_p,POINTER(c_char_p))
