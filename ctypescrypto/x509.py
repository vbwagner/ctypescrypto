from ctypes import c_void_p,create_string_buffer,c_long,c_int
from ctypescrypto.bio import Membio
from ctypescrypto.pkey import PKey
from ctypescrypto.oid import Oid
from ctypescrypto.exception import LibCryptoError
from ctypescrypto import libcrypto

class X509Error(LibCryptoError):
	"""
	Exception, generated when some openssl function fail
	during X509 operation
	"""
	pass


class X509Name:
	"""
	Class which represents X.509 distinguished name - typically 
	a certificate subject name or an issuer name.
	"""
	# XN_FLAG_SEP_COMMA_PLUS & ASN1_STRFLG_UTF8_CONVERT
	PRINT_FLAG=0x10010
	ESC_MSB=4
	def __init__(self,ptr=None,copy=False):
		"""
		Creates a X509Name object
		@param ptr - pointer to X509_NAME C structure (as returned by some  OpenSSL functions
		@param copy - indicates that this structure have to be freed upon object destruction
		"""
		if ptr is not None:
			self.ptr=ptr
			self.need_free=copy
			self.writable=False
		else:
			self.ptr=libcrypto.X509_NAME_new()
			self.need_free=True
			self.writable=True
	def __del__(self):
		"""
		Frees if neccessary
		"""
		if self.need_free:
			libcrypto.X509_NAME_free(self.ptr)
	def __str__(self):
		"""
		Produces an ascii representation of the name, escaping all symbols > 0x80
		Probably it is not what you want, unless your native language is English
		"""
		b=Membio()
		libcrypto.X509_NAME_print_ex(b.bio,self.ptr,0,self.PRINT_FLAG | self.ESC_MSB)
		return str(b)
	def __unicode__(self):
		"""
		Produces unicode representation of the name. 
		"""
		b=Membio()
		libcrypto.X509_NAME_print_ex(b.bio,self.ptr,0,self.PRINT_FLAG)
		return unicode(b)
	def __len__(self):
		"""
		return number of components in the name
		"""
		return libcrypto.X509_NAME_entry_count(self.ptr)
	def __cmp__(self,other):
		"""
		Compares X509 names
		"""
		return libcrypto.X509_NAME_cmp(self.ptr,other.ptr)
	def __eq__(self,other):
		return libcrypto.X509_NAME_cmp(self.ptr,other.ptr)==0

	def __getitem__(self,key):
		if isinstance(key,Oid):
			# Return first matching field
			idx=libcrypto.X509_NAME_get_index_by_NID(self.ptr,key.nid,-1)
			if idx<0:
				raise KeyError("Key not found "+repr(Oid))
			entry=libcrypto.X509_NAME_get_entry(self.ptr,idx)
			s=libcrypto.X509_NAME_ENTRY_get_data(entry)
			b=Membio()
			libcrypto.ASN1_STRING_print_ex(b.bio,s,self.PRINT_FLAG)
			return unicode(b)
		elif isinstance(key,int):
			# Return OID, string tuple
			entry=libcrypto.X509_NAME_get_entry(self.ptr,key)
			if entry is None:
				raise IndexError("name entry index out of range")
			obj=libcrypto.X509_NAME_ENTRY_get_object(entry)
			nid=libcrypto.OBJ_obj2nid(obj)
			if nid==0:
				buf=create_string_buffer(80)
				len=libcrypto.OBJ_obj2txt(buf,80,obj,1)
				oid=Oid(buf[0:len])
			else:
				oid=Oid(nid)
			s=libcrypto.X509_NAME_ENTRY_get_data(entry)
			b=Membio()
			libcrypto.ASN1_STRING_print_ex(b.bio,s,self.PRINT_FLAG)
			return (oid,unicode(b))

	def __setitem__(self,key,val):
		if not self.writable:
			raise ValueError("Attempt to modify constant X509 object")
class X509_extlist:
	def __init__(self,ptr):
		self.ptr=ptr
	def __del__(self):
		libcrypto.X509_NAME_free(self.ptr)
	def __str__(self):
		raise NotImplementedError
	def __len__(self):
		return libcrypto.X509_NAME_entry_count(self.ptr)

	def __getattr__(self,key):
	  	raise NotImplementedError
	def __setattr__(self,key,val):
		raise NotImplementedError

	


class X509:
	"""
	Represents X.509 certificate. 
	"""
	def __init__(self,data=None,ptr=None,format="PEM"):
		"""
		Initializes certificate
		@param data - serialized certificate in PEM or DER format.
		@param ptr - pointer to X509, returned by some openssl function. 
			mutually exclusive with data
		@param format - specifies data format. "PEM" or "DER", default PEM
		"""
		if ptr is not None:
			if data is not None: 
				raise TypeError("Cannot use data and ptr simultaneously")
			self.cert = ptr
		elif data is None:
			raise TypeError("data argument is required")
		else:
			b=Membio(data)
			if format == "PEM":
				self.cert=libcrypto.PEM_read_bio_X509(b.bio,None,None,None)
			else:
				self.cert=libcrypto.d2i_X509_bio(b.bio,None)
			if self.cert is None:
				raise X509Error("error reading certificate")
	def __del__(self):
		"""
		Frees certificate object
		"""
		libcrypto.X509_free(self.cert)
	def __str__(self):
		""" Returns der string of the certificate """
		b=Membio()
		if libcrypto.i2d_X509_bio(b.bio,self.cert)==0:
			raise X509Error("error serializing certificate")
		return str(b)
	def __repr__(self):
		""" Returns valid call to the constructor """
		return "X509(data="+repr(str(self))+",format='DER')"
	@property
	def pubkey(self):
		"""EVP PKEy object of certificate public key"""
		return PKey(ptr=libcrypto.X509_get_pubkey(self.cert,False))
	def verify(self,store=None,key=None):	
		""" 
		Verify self. Supports verification on both X509 store object 
		or just public issuer key
		@param store X509Store object.
		@param key - PKey object
		parameters are mutually exclusive. If neither is specified, attempts to verify
		itself as self-signed certificate
		"""
		if store is not None and key is not None:
			raise X509Error("key and store cannot be specified simultaneously")
		if store is not None:
			ctx=libcrypto.X509_STORE_CTX_new()
			if ctx is None:
				raise X509Error("Error allocating X509_STORE_CTX")
			if libcrypto.X509_STORE_CTX_init(ctx,store.ptr,self.cert,None) < 0:
				raise X509Error("Error allocating X509_STORE_CTX")
			res= libcrypto.X509_verify_cert(ctx)
			libcrypto.X509_STORE_CTX_free(ctx)
			return res>0
		else:
			if key is None:
				if self.issuer != self.subject:
					# Not a self-signed certificate
					return False
				key = self.pubkey
			res = libcrypto.X509_verify(self.cert,key.key)
			if res < 0:
				raise X509Error("X509_verify failed")
			return res>0
			
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
		asnint=libcrypto.X509_get_serialNumber(self.cert)
		b=Membio()
		libcrypto.i2a_ASN1_INTEGER(b.bio,asnint)
		return int(str(b),16)
	@property
	def startDate(self):
		""" Certificate validity period start date """
		# Need deep poke into certificate structure (x)->cert_info->validity->notBefore	
		raise NotImplementedError
	@property
	def endDate(self):
		""" Certificate validity period end date """
		# Need deep poke into certificate structure (x)->cert_info->validity->notAfter
		raise NotImplementedError
	def extensions(self):
		""" Returns list of extensions """
		raise NotImplementedError
	def check_ca(self):
		""" Returns True if certificate is CA certificate """
		return libcrypto.X509_check_ca(self.cert)>0
class X509Store:
	"""
		Represents trusted certificate store. Can be used to lookup CA certificates to verify

		@param file - file with several certificates and crls to load into store
		@param dir - hashed directory with certificates and crls
		@param default - if true, default verify location (directory) is installed

	"""
	def __init__(self,file=None,dir=None,default=False):
		"""
		Creates X509 store and installs lookup method. Optionally initializes 
		by certificates from given file or directory.
		"""
		#
		# Todo - set verification flags
		# 
		self.store=libcrypto.X509_STORE_new()
		lookup=libcrypto.X509_STORE_add_lookup(self.store,libcrypto.X509_LOOKUP_file())
		if lookup is None:
			raise X509Error("error installing file lookup method")
		if (file is not None):
			if not libcrypto.X509_LOOKUP_loadfile(lookup,file,1):
				raise X509Error("error loading trusted certs from file "+file)
		
		lookup=libcrypto.X509_STORE_add_lookup(self.store,libcrypto.X509_LOOKUP_hash_dir())
		if lookup is None:
			raise X509Error("error installing hashed lookup method")
		if dir is not None:
			if not libcrypto.X509_LOOKUP_add_dir(lookup,dir,1):
				raise X509Error("error adding hashed  trusted certs dir "+dir)
		if default:
			if not libcrypto.X509_LOOKUP.add_dir(lookup,None,3):
				raise X509Error("error adding default trusted certs dir ")
	def add_cert(self,cert):
		"""
		Explicitely adds certificate to set of trusted in the store
		@param cert - X509 object to add
		"""
		if not isinstance(cert,X509):
			raise TypeError("cert should be X509")
		libcrypto.X509_STORE_add_cert(self.store,cert.cert)
	def add_callback(self,callback):
		"""
		Installs callbac function, which would receive detailed information
		about verified ceritificates
		"""
		raise NotImplementedError
	def setflags(self,flags):
		"""
		Set certificate verification flags.
		@param flags - integer bit mask. See OpenSSL X509_V_FLAG_* constants
		"""
		libcrypto.X509_STORE_set_flags(self.store,flags)	
	def setpurpose(self,purpose):
		"""
		Sets certificate purpose which verified certificate should match
		@param purpose - number from 1 to 9 or standard strind defined in Openssl
		possible strings - sslcient,sslserver, nssslserver, smimesign,smimeencrypt, crlsign, any,ocsphelper
		"""
		if isinstance(purpose,str):
			purp_no=X509_PURPOSE_get_by_sname(purpose)
			if purp_no <=0:
				raise X509Error("Invalid certificate purpose '"+purpose+"'")
		elif isinstance(purpose,int):
			purp_no = purpose
		if libcrypto.X509_STORE_set_purpose(self.store,purp_no)<=0:
			raise X509Error("cannot set purpose")
libcrypto.i2a_ASN1_INTEGER.argtypes=(c_void_p,c_void_p)
libcrypto.ASN1_STRING_print_ex.argtypes=(c_void_p,c_void_p,c_long)
libcrypto.X509_get_serialNumber.argtypes=(c_void_p,)
libcrypto.X509_get_serialNumber.restype=c_void_p
libcrypto.X509_NAME_ENTRY_get_object.restype=c_void_p
libcrypto.X509_NAME_ENTRY_get_object.argtypes=(c_void_p,)
libcrypto.OBJ_obj2nid.argtypes=(c_void_p,)
libcrypto.X509_NAME_get_entry.restype=c_void_p
libcrypto.X509_NAME_get_entry.argtypes=(c_void_p,c_int)
