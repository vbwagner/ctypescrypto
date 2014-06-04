from ctypes import c_void_p
from ctypescrypto.bio import Membio
from ctypescrypto.exception import LibCryptoError
from crypescrypto import libcrypto

class X509Name:
	def __init__(self,ptr):
		self.ptr=ptr
	def __del__(self):
		libcrypto.X509_NAME_free(self.ptr)
	def __str__(self):

	def __len__(self):
		return libcrypto.X509_NAME_entry_count(self.ptr)

	def __getattr__(self,key):
	  
	def __setattr__(self,key,val):

class X509_extlist:
	def __init__(self,ptr):
		self.ptr=ptr
	def __del__(self):
		libcrypto.X509_NAME_free(self.ptr)
	def __str__(self):

	def __len__(self):
		return libcrypto.X509_NAME_entry_count(self.ptr)

	def __getattr__(self,key):
	  
	def __setattr__(self,key,val):


	


class X509:
	def __init__(self,ptr):
		self.cert = ptr
	def __del__(self):
		libcrypto.X509_free(self.cert)
	def __str__(self):
		""" Returns der string of the certificate """
	def pubkey(self):
		""" Returns EVP PKEy object of certificate public key"""
		return PKey(libcrypto.X509_get_pubkey(self.cert,False)
	def verify(self,key):	
		""" Verify self on given issuer key """
	def frompem(s):
		""" Create X509 object from pem string """
	def fromder(s):
		""" Create X509 object from der string """
	def subject(self):
		return X509Name(libcrypto.X509_get_subject_name(self.cert))
	def issuer(self):
		return X509Name(libcrypto.X509_get_issuer_name(self.cert))
	def serial(self):
		return

	def startDate(self):

	def endDate(self);

	def extensions(self):
