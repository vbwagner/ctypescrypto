from ctypes import c_void_p
from ctypescrypto.bio import Membio
from ctypescrypto.pkey import PKey
from ctypescrypto.oid import Oid
from ctypescrypto.exception import LibCryptoError
from ctypescrypto import libcrypto

class X509Error(LibCryptoError):
	pass


class X509Name:
	def __init__(self,ptr):
		self.ptr=ptr
	def __del__(self):
		libcrypto.X509_NAME_free(self.ptr)
	def __str__(self):
		b=Membio()
		libcrypto.X509_NAME_print_ex(b.bio,self.ptr,0,PRING_FLAG)
		return str(b).decode("utf-8")

	def __len__(self):
		return libcrypto.X509_NAME_entry_count(self.ptr)

	def __getattr__(self,key):
		if isinstance(key,Oid):
		# Return list of strings
	  		raise NotImpemented	
		elif isinstance(key,int):
			# Return OID, sting tuple
			raise NotImplemented
		else:
			raise TypeError("X509 name can be indexed with oids and numbers only")

	def __setattr__(self,key,val):
		pass
class X509_extlist:
	def __init__(self,ptr):
		self.ptr=ptr
	def __del__(self):
		libcrypto.X509_NAME_free(self.ptr)
	def __str__(self):
		raise NotImplemented
	def __len__(self):
		return libcrypto.X509_NAME_entry_count(self.ptr)

	def __getattr__(self,key):
	  	raise NotImplemented
	def __setattr__(self,key,val):
		raise NotImplemented

	


class X509:
	def __init__(self,data=None,ptr=None,format="PEM"):
		if ptr is not None:
			if data is not None: 
				raise TypeError("Cannot use data and ptr simultaneously")
			self.cert = ptr
		elif data is None:
			raise TypeError("data argument is required")
			b=Membio(data)
			if format == "PEM":
				self.cert=libcrypto.PEM_read_bio_X509(b.bio,None,None,None)
			else:
				self.cert=libcrypto.d2i_X509_bio(b.bio,None)
			if self.cert is None:
				raise X509Error("error reading certificate")
	def __del__(self):
		libcrypto.X509_free(self.cert)
	def __str__(self):
		""" Returns der string of the certificate """
		b=Membio()
		if libcrypto.i2d_X509_bio(b.bio,self.cert)==0:
			raise X509Error("error serializing certificate")
	@property
	def pubkey(self):
		"""EVP PKEy object of certificate public key"""
		return PKey(ptr=libcrypto.X509_get_pubkey(self.cert,False))
	def verify(self,key):	
		""" Verify self on given issuer key """
	@property
	def subject(self):
		""" X509Name for certificate subject name """
		return X509Name(libcrypto.X509_get_subject_name(self.cert))
	@property
	def issuer(self):
		""" X509Name for certificate issuer name """
		return X509Name(libcrypto.X509_get_issuer_name(self.cert))
	@property
	def serial(self):
		""" Serial number of certificate as integer """
		return
	@property
	def startDate(self):
		""" Certificate validity period start date """
		raise NotImplemented
	@property
	def endDate(self):
		""" Certificate validity period end date """
		raise NotImplemented
	def extensions(self):
		raise NotImplemented
