from ctypes import c_char_p,c_void_p,byref,c_int,c_long, c_longlong, create_string_buffer,CFUNCTYPE,POINTER
from ctypescrypto import libcrypto
from ctypescrypto.exception import LibCryptoError,clear_err_stack
from ctypescrypto.bio import Membio

class PKeyError(LibCryptoError):
	pass

CALLBACK_FUNC=CFUNCTYPE(c_int,c_char_p,c_int,c_int,c_char_p)
def password_callback(buf,length,rwflag,u):
	cnt=len(u)
	if length<cnt:
		cnt=length
	memmove(buf,u,cnt)
	return cnt

_cb=CALLBACK_FUNC(password_callback)

class PKey:
	def __init__(self,ptr=None,privkey=None,pubkey=None,format="PEM",cansign=False,password=None):
		if not ptr is None:
			self.key=ptr
			self.cansign=cansign
			if not privkey is None or not pubkey is None:
				raise TypeError("Just one of pubkey or privkey can be specified")
		elif not privkey is None:
			if not pubkey is None:
				raise TypeError("Just one of pubkey or privkey can be specified")
			b=Membio(privkey)
			self.cansign=True
			if format == "PEM":
				self.key=libcrypto.PEM_read_bio_PrivateKey(b.bio,None,_cb,c_char_p(password))
			else: 
				self.key=libcrypto.d2i_PrivateKey_bio(b.bio,None)
			if self.key is None:
				raise PKeyError("error parsing private key")
		elif not pubkey is None:
			b=Membio(pubkey)
			self.cansign=False
			if format == "PEM":
				self.key=libcrypto.PEM_read_bio_PUBKEY(b.bio,None,_cb,None)
			else:
				self.key=libcrypto.d2i_PUBKEY_bio(b.bio,None)
			if self.key is None:
				raise PKeyError("error parsing public key")
		else:
			raise TypeError("Neither public, nor private key is specified")
			

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
		libcrypto.EVP_PKEY_print_public(b.bio,self.key,0,None)
		return str(b)

	def sign(self,digest,**kwargs):
		"""
			Signs given digest and retirns signature
			Keyword arguments allows to set various algorithm-specific
			parameters. See pkeyutl(1) manual.
		"""
		ctx=libcrypto.EVP_PKEY_CTX_new(self.key,None)
		if ctx is None:
			raise PKeyError("Initailizing sign context")
		if libcrypto.EVP_PKEY_sign_init(ctx)<1:
			raise PKeyError("sign_init")
		for oper in kwargs:
			rv=libcrypto.EVP_PKEY_CTX_ctrl_str(ctx,oper,kwargs[oper])
			if rv==-2:
				raise PKeyError("Parameter %s is not supported by key"%(oper))
			if rv<1:
				raise PKeyError("Error setting parameter %s"(oper))
		# Find out signature size
		siglen=c_long(0)
		if libcrypto.EVP_PKEY_sign(ctx,None,byref(siglen),digest,len(digest))<1:
			raise PKeyError("signing")	
		sig=create_string_buffer(siglen.value)
		libcrypto.EVP_PKEY_sign(ctx,sig,byref(siglen),digest,len(digest))
		libcrypto.EVP_PKEY_CTX_free(ctx)
		return sig.raw[:siglen.value]

	def verify(self,digest,signature,**kwargs):
		"""
			Verifies given signature on given digest
			Returns True if Ok, False if don't match
		"""
		ctx=libcrypto.EVP_PKEY_CTX_new(self.key,None)
		if ctx is None:
			raise PKeyError("Initailizing verify context")
		if libcrypto.EVP_PKEY_verify_init(ctx)<1:
			raise PKeyError("verify_init")
		for oper in kwargs:
			rv=libcrypto.EVP_PKEY_CTX_ctrl_str(ctx,oper,kwargs[oper])
			if rv==-2:
				raise PKeyError("Parameter %s is not supported by key"%(oper))
			if rv<1:
				raise PKeyError("Error setting parameter %s"(oper))
		rv=libcrypto.EVP_PKEY_verify(ctx,signature,len(signature),digest,len(digest))
		if rv<0:
			raise PKeyError("Signature verification")
		libcrypto.EVP_PKEY_CTX_free(ctx)
		return rv>0
	def derive(self,peerkey,**kwargs):
		"""
			Derives shared key (DH,ECDH,VKO 34.10). Requires
			private key available

			@param peerkey - other key (may be public only)

			Keyword parameters are algorithm-specific
		"""
		ctx=libcrypto.EVP_PKEY_CTX_new(self.key,None)
		if ctx is None:
			raise PKeyError("Initailizing derive context")
		if libcrypto.EVP_PKEY_derive_init(ctx)<1:
			raise PKeyError("derive_init")
		for oper in kwargs:
			rv=libcrypto.EVP_PKEY_CTX_ctrl_str(ctx,oper,kwargs[oper])
			if rv==-2:
				raise PKeyError("Parameter %s is not supported by key"%(oper))
			if rv<1:
				raise PKeyError("Error setting parameter %s"(oper))
		if libcrypto.EVP_PKEY_derive_set_peer(ctx,peerkey.key)<=0:
			raise PKeyError("Cannot set peer key")
		keylen=c_long(0)
		if libcrypto.EVP_PKEY_derive(ctx,None,byref(keylen))<=0:
			raise PKeyError("computing shared key length")
		buf=create_string_buffer(keylen)
		if libcrypto.EVP_PKEY_derive(ctx,buf,byref(keylen))<=0:
			raise PKeyError("computing actual shared key")
		libcrypto.EVP_PKEY_CTX_free(ctx)
		return buf.raw[:keylen]
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
			if rw==-2:
				raise PKeyError("Parameter %s is not supported by key"%(oper))
			if rv<1:
				raise PKeyError("Error setting parameter %s"(oper))
		key=c_void_p(None)
		if libcrypto.EVP_PKEY_keygen(ctx,byref(key))<=0:
			raise PKeyError("Error generating key")
		libcrypto.EVP_PKEY_CTX_free(ctx)
		return PKey(ptr=key,cansign=True)

# Declare function prototypes
libcrypto.EVP_PKEY_cmp.argtypes=(c_void_p,c_void_p)
libcrypto.PEM_read_bio_PrivateKey.restype=c_void_p
libcrypto.PEM_read_bio_PrivateKey.argtypes=(c_void_p,POINTER(c_void_p),CALLBACK_FUNC,c_char_p) 
libcrypto.d2i_PKCS8PrivateKey_bio.restype=c_void_p
libcrypto.d2i_PKCS8PrivateKey_bio.argtypes=(c_void_p,POINTER(c_void_p),CALLBACK_FUNC,c_char_p)
libcrypto.PEM_read_bio_PUBKEY.restype=c_void_p
libcrypto.PEM_read_bio_PUBKEY.argtypes=(c_void_p,POINTER(c_void_p),CALLBACK_FUNC,c_char_p)
libcrypto.d2i_PUBKEY_bio.restype=c_void_p
libcrypto.d2i_PUBKEY_bio.argtypes=(c_void_p,c_void_p)
libcrypto.EVP_PKEY_print_public.argtypes=(c_void_p,c_void_p,c_int,c_void_p)

