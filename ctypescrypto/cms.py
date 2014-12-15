"""
Implements operations with CMS EnvelopedData and SignedData messages

Contains function CMS() which parses CMS message and creates either
EnvelopedData or SignedData objects (EncryptedData and CompressedData
can be easily added, because OpenSSL contain nessesary function)

Each of these objects contains create() static method which is used to
create it from raw data and neccessary certificates.


"""
from ctypes import c_int, c_void_p, c_char_p, c_int
from ctypescrypto.exception import LibCryptoError
from ctypescrypto import libcrypto
from ctypescrypto.bio import Membio
from ctypescrypto.oid import Oid

class CMSError(LibCryptoError):
	"""
	Exception which is raised when error occurs
	"""
	pass

class Flags:
	"""
	Constants for flags passed to the CMS methods. 
	Can be OR-ed together
	"""
	TEXT=1
	NOCERTS=2
	NO_CONTENT_VERIFY=4
	NO_ATTR_VERIFY=8
	NO_SIGS=NO_CONTENT_VERIFY|NO_ATTR_VERIFY
	NOINTERN=0x10
	NO_SIGNER_CERT_VERIFY=0x20
	NO_VERIFY=0x20
	DETACHED=0x40
	BINARY=0x80
	NOATTR=0x100
	NOSMIMECAP =0x200
	NOOLDMIMETYPE=0x400
	CRLFEOL=0x800
	STREAM=0x1000
	NOCRL=0x2000
	PARTIAL=0x4000
	REUSE_DIGEST=0x8000
	USE_KEYID=0x10000
	DEBUG_DECRYPT=0x20000

def CMS(data,format="PEM"):
	"""
	Parses CMS data and returns either SignedData or EnvelopedData
	object
	"""
	b=Membio(data)
	if format == "PEM":
		ptr=libcrypto.PEM_read_bio_CMS(b.bio,None,None,None)
	else:
		ptr=libcrypto.d2i_CMS_bio(b.bio,None)
	typeoid = Oid(libcrypto.OBJ_obj2nid(libcrypto.CMS_get0_type(ptr)))
	if typeoid.shortname()=="pkcs7-signedData":
		return SignedData(ptr)
	elif typeoid.shortname()=="pkcs7-envelopedData":
		return EnvelopedData(ptr)
	elif typeoid.shortname()=="pkcs7-encryptedData":
		return EncryptedData(ptr)
	else:
		raise NotImplementedError("cannot handle "+typeoid.shortname())

class CMSBase: 
	"""
	Common ancessor for all CMS types.
	Implements serializatio/deserialization
	"""
	def __init__(self,ptr=None):
		self.ptr=ptr
	def __str__(self):
		"""
		Serialize in DER format
		"""
		b=Membio()
		if not libcrypto.i2d_CMS_bio(b.bio,self.ptr):
			raise CMSError("writing CMS to PEM")
		return str(b)

	def pem(self):
		"""
		Serialize in PEM format
		"""
		b=Membio()
		if not libcrypto.PEM_write_bio_CMS(b.bio,self.ptr):
			raise CMSError("writing CMS to PEM")
		return str(b)
		
	
		
class SignedData(CMSBase):
	@staticmethod
	def create(data,cert,pkey,flags=Flags.BINARY,certs=[]):
		"""
			Creates SignedData message by signing data with pkey and
			certificate.

			@param data - data to sign
			@param pkey - pkey object with private key to sign
			@param flags - OReed combination of Flags constants
			@param certs - list of X509 objects to include into CMS
		"""
		if not pkey.cansign:
			raise ValueError("Specified keypair has no private part")
		if cert.pubkey!=pkey:
			raise ValueError("Certificate doesn't match public key")
		b=Membio(data)
		if certs is not None and len(certs)>0:
			certstack=StackOfX509(certs)
		else:
			certstack=None
		ptr=libcrypto.CMS_sign(cert.cert,pkey.ptr,certstack,b.bio,flags)
		if ptr is None:
			raise CMSError("signing message")
		return SignedData(ptr)
	def sign(self,cert,pkey,md=None,data=None,flags=Flags.BINARY):
		"""
			Adds another signer to already signed message
			@param cert - signer's certificate
			@param pkey - signer's private key
			@param md - message digest to use as DigestType object 
				(if None - default for key would be used)
			@param data - data to sign (if detached and
					Flags.REUSE_DIGEST is not specified)
			@param flags - ORed combination of Flags consants
		"""
		if not pkey.cansign:
			raise ValueError("Specified keypair has no private part")
		if cert.pubkey!=pkey:
			raise ValueError("Certificate doesn't match public key")
		p1=libcrypto.CMS_sign_add1_Signer(self.ptr,cert.cert,pkey.ptr,
			md.digest,flags)
		if p1 is None:
			raise CMSError("adding signer")
		if flags & Flags.REUSE_DIGEST==0:
			if data is not None:
				b=Membio(data)
				biodata=b.bio
			else:
				biodata=None
			res= libcrypto.CMS_final(self.ptr,biodata,None,flags)
			if res<=0:
				raise CMSError
	def verify(self,store,flags,data=None,certs=[]):
		"""
		Verifies signature under CMS message using trusted cert store

		@param store -  X509Store object with trusted certs
		@param flags - OR-ed combination of flag consants
		@param data - message data, if messge has detached signature
		param certs - list of certificates to use during verification
				If Flags.NOINTERN is specified, these are only
				sertificates to search for signing certificates
		@returns True if signature valid, False otherwise
		"""
		bio=None
		if data!=None:
			b=Membio(data)
			bio=b.bio
		if certs is not None and len(certs)>0:
			certstack=StackOfX509(certs)
		else:
			certstack=None
		res=libcrypto.CMS_verify(self.ptr,certstack,store.store,bio,None,flags)
		return res>0
	@property	
	def signers(self,store=None):
		"""
		Return list of signer's certificates
		"""
		p=libcrypto.CMS_get0_signers(self.ptr)
		if p is None:
			raise CMSError
		return StackOfX509(ptr=p,disposable=False)
	@property
	def data(self):
		"""
		Returns signed data if present in the message
		"""
		b=Membio()
		if not libcrypto.CMS_verify(self.ptr,None,None,None,b.bio,Flags.NO_VERIFY):
			raise CMSError("extract data")
		return str(b)
	def addcert(self,cert):
		"""
		Adds a certificate (probably intermediate CA) to the SignedData
		structure
		"""
		if libcrypto.CMS_add1_cert(self.ptr,cert.cert)<=0:
			raise CMSError("adding cert")
	def addcrl(self,crl):
		"""
		Adds a CRL to the signed data structure
		"""
		raise NotImplementedError
	@property
	def certs(self):
		"""
		List of the certificates contained in the structure
		"""
		p=CMS_get1_certs(self.ptr)
		if p is None:
			raise CMSError("getting certs")
		return StackOfX509(ptr=p,disposable=True)
	@property
	def crls(self):
		"""
		List of the CRLs contained in the structure
		"""
		raise NotImplementedError

class EnvelopedData(CMSBase):
	@staticmethod
	def create(recipients,data,cipher,flags=0):
		"""
		Creates and encrypts message
		@param recipients - list of X509 objects
		@param data - contents of the message
		@param cipher - CipherType object
		@param flags - flag
		"""
		recp=StackOfX509(recipients)
		b=Membio(data)
		p=libcrypto.CMS_encrypt(recp.ptr,b.bio,cipher.cipher_type,flags)
		if p is None:
			raise CMSError("encrypt EnvelopedData")
		return EnvelopedData(p)
	def decrypt(self,pkey,cert,flags=0):
		"""
		Decrypts message
		@param pkey - private key to decrypt
		@param cert - certificate of this private key (to find
			neccessary RecipientInfo
		@param flags - flags
		@returns - decrypted data
		"""
		if not pkey.cansign:
			raise ValueError("Specified keypair has no private part")
		if pkey != cert.pubkey:
			raise ValueError("Certificate doesn't match private key")
		b=Membio()
		res=libcrypto.CMS_decrypt(self.ptr,pkey.ptr,cert.ccert,None,b.bio,flags)
		if res<=0:
			raise CMSError("decrypting CMS")
		return str(b)

class EncryptedData(CMSBase):
	@staticmethod
	def create(data,cipher,key,flags=0):
		"""
		Creates an EncryptedData message.
		@param data data to encrypt
		@param cipher cipher.CipherType object represening required
				cipher type
		@param key - byte array used as simmetic key
		@param flags - OR-ed combination of Flags constant
		"""
		b=Membio(data)
		ptr=libcrypto.CMS_EncryptedData_encrypt(b.bio,cipher.cipher_type,key,len(key),flags)
		if ptr is None:
			raise CMSError("encrypt data")
		return EncryptedData(ptr)
	def decrypt(self,key,flags=0):
		"""
		Decrypts encrypted data message
		@param key - symmetic key to decrypt
		@param flags - OR-ed combination of Flags constant
		"""
		b=Membio()
		if libcrypto.CMS_EncryptedData_decrypt(self.ptr,key,len(key),None,
			b.bio,flags)<=0:
				raise CMSError("decrypt data")
		return str(b)

__all__=['CMS','CMSError','Flags','SignedData','EnvelopedData','EncryptedData']

libcrypto.CMS_verify.restype=c_int
libcrypto.CMS_verify.argtypes=(c_void_p,c_void_p,c_void_p,c_void_p,c_void_p,c_int)
