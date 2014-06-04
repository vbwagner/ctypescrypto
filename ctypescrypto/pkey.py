from ctypes import byref,c_int,c_long, c_longlong, create_string_buffer
from ctypescrypto import libcrypto
from ctypescrypto.exception import LibCryptoErrors,clear_err_stack
from ctypescrypto.bio import Membio

class PKeyError(LibCryptoError):
	pass

class PKey:
	def __init__(self,ptr,cansign)
		self.key=ptr:
		self.cansign=cansign
	def __del__(self):
		libcrypto.EVP_PKEY_free(self.key)
	def __eq__(self,other):
		""" Compares two public keys. If one has private key and other
			doesn't it doesn't affect result of comparation
		"""
		return libcrypto.EVP_PKEY_cmp(self.key,other.key)==1
	def __ne__(self,other):
		return not self.__eq__(other)
	def __str__(self):
		""" printable representation of public key """	
		b=Membio()
		libcrypto.EVP_PKEY_print_public(b.bio,self.key,0,NULL)
		return str(b)
	def privpem(s,password=None):
		""" Class method for load from the pem string of private key """
		b=Membio(s)
		return PKey(libcrypto.PEM_read_bio_PrivateKey(b.bio,NULL,cb,c_char_p(password))

	def privder(s):
		""" Class method for load from the binary ASN1 structure of private key """
		b=Membio(s)
		return PKey(libcrypto.d2i_PrivateKey_bio(b.bio,NULL),True)
	def pubpem(s):
		""" Class method for load from public key pem string"""
		b=Membio(s)
		return PKey(libcrypto.PEM_read_bio_PUBKEY(b.bio,NULL,cb,c_char_p(password)),False)
	def pubder(s):
		""" Class method for load from the binary ASN1 structure """
		b=Membio(s)
		return PKey(libcrypto.d2i_PUBKEY_bio(b.bio,NULL),False)
	def sign(self,digest,**kwargs):
		"""
			Signs given digest and retirns signature
			Keyword arguments allows to set various algorithm-specific
			parameters. See pkeyutl(1) manual.
		"""
		ctx=libcrypto.EVP_PKEY_CTX_new(self.key,None)
		if ctx is None:
			raise PkeyError("Initailizing sign context")
		if libcrypto.EVP_PKEY_sign_init(ctx)<1:
			raise PkeyError("sign_init")
		for oper in kwargs:
			rv=libcrypto.EVP_PKEY_CTX_ctrl_str(ctx,oper,kwargs[oper])
			if rw=-2:
				raise PKeyError("Parameter %s is not supported by key"%(oper))
			if rv<1:
				raise PKeyError("Error setting parameter %s"(oper))
		# Find out signature size
		siglen=c_long(0)
		if libcrypto.EVP_PKEY_sign(ctx,None,byref(siglen),digest,len(digest))<1:
			raise PkeyError("signing")	
		sig=create_string_buffer(siglen.value)
		libcrypto.EVP_PKEY_sign(ctx,sig,byref(signlen),digest,len(digest)
		libcrypto.EVP_PKEY_CTX_free(ctx)
		return sig.value[:siglen.value]

	def verify(self,digest,signature,**kwargs):
		"""
			Verifies given signature on given digest
			Returns True if Ok, False if don't match
		"""
		ctx=libcrypto.EVP_PKEY_CTX_new(self.key,None)
		if ctx is None:
			raise PkeyError("Initailizing verify context")
		if libcrypto.EVP_PKEY_verify_init(ctx)<1:
			raise PkeyError("verify_init")
		for oper in kwargs:
			rv=libcrypto.EVP_PKEY_CTX_ctrl_str(ctx,oper,kwargs[oper])
			if rw=-2:
				raise PKeyError("Parameter %s is not supported by key"%(oper))
			if rv<1:
				raise PKeyError("Error setting parameter %s"(oper))
		rv=libcrypto.EVP_PKEY_verify(ctx,signature,len(signature),digest,len(digest))
		if rv<0:
			raise PKeyError("Signature verification")
		libcrypto=EVP_PKEY_CTX_free(ctx)
		return rv>0
	def generate(algorithm,**kwargs):
		"""
			Generates new private-public key pair for given algorithm
			(string like 'rsa','ec','gost2001') and algorithm-specific
			parameters
		"""
		tmpeng=c_void_p(None)
		ameth=libcrypto.EVP_PKEY_asn1_find_str(byref(tmpeng),algorithm,-1)
		if ameth is None:
			raise PKeyError("Algorithm %s not foind\n"%(algname))
		clear_err_stack()
		pkey_id=c_int(0)
		libcrypto.EVP_PKEY_asn1_get0_info(byref(pkey_id),None,None,None,None,ameth)
		libcrypto.ENGINE_finish(tmpeng)
		ctx=libcrypto.EVP_PKEY_CTX_new_id(pkey_id)
		if ctx is None:
			raise PKeyError("Creating context for key type %d"%(pkey_id.value)) 
		if libcrypto.EVP_PKEY_keygen_init(ctx) <=0 :
			raise PKeyError("keygen_init")
		for oper in kwargs:
			rv=libcrypto.EVP_PKEY_CTX_ctrl_str(ctx,oper,kwargs[oper])
			if rw=-2:
				raise PKeyError("Parameter %s is not supported by key"%(oper))
			if rv<1:
				raise PKeyError("Error setting parameter %s"(oper))
		key=c_void_p(None)
		if libcrypto.EVP_PKEY_keygen(ctx,byref(key))<=0:
			raise PKeyError("Error generating key")
		libcrypto.EVP_PKEY_CTX_free(ctx)
		return PKey(key,True)
			
