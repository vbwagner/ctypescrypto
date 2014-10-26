"""
Implements operations with CMS EnvelopedData and SignedData messages

Contains function CMS() which parses CMS message and creates either
EnvelopedData or SignedData objects (EncryptedData and CompressedData
can be easily added, because OpenSSL contain nessesary function)

Each of these objects contains create() static method which is used to
create it from raw data and neccessary certificates.


"""

from ctypescrypto.exception import LibCryptoError
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
	else:
		raise NotImplementedError("cannot handle "+typeoid.shortname())


	
		
class SignedData:
	def __init__(self,ptr=None):
		self.ptr=ptr
	@staticmethod
	def create(data,cert,pkey,flags=Flags.BINARY):
		"""
			Creates SignedData message by signing data with pkey and
			certificate.

			@param data - data to sign
			@param pkey - pkey object with private key to sign
		"""
		if not pkey.cansign:
			raise ValueError("Specified keypair has no private part")
		if cert.pubkey!=pkey:
			raise ValueError("Certificate doesn't match public key")
		b=Membio(data)
		ptr=libcrypto.CMS_sign(cert.cert,pkey.ptr,None,b.bio,flags)
		if ptr is None:
			raise CMSError("signing message")
		return SignedData(ptr)
	def sign(self,cert,pkey,md=None,data=None,flags=Flags.BINARY):
		"""
			Adds another signer to already signed message
			@param cert - signer's certificate
			@param pkey - signer's private key
			@param data - data to sign (if detached)
			@param md - message digest to use as DigestType object (if None - default for key
				would be used)
			@param flags - flags
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
	def verify(self,store,flags,data=None):
		bio=None
		if data!=None:
			b=Membio(data)
			bio=b.bio
		res=libcrypto.CMS_verify(self.ptr,store.store,bio,None,flags)
		return res>0
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
		
	@property	
	def signers(self,store=None):
		"""
		Return list of signer's certificates
		"""
		raise NotImplementedError
	@property
	def data(self):
		"""
		Returns signed data if present
		"""
		raise NotImplementedError
	def addcert(self,cert):
		"""
		Adds a certificate (probably intermediate CA) to the SignedData
		structure
		"""
		raise NotImplementedError
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
		raise NotImplementedError
	@property
	def crls(self):
		"""
		List of the CRLs contained in the structure
		"""
		raise NotImplementedError

class EnvelopedData:
	def __init__(self,ptr):
		"""
		Initializes an object. For internal use
		"""
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
	@staticmethod
	def create(recipients,data,cipher,flags=0):
		"""
		Creates and encrypts message
		@param recipients - list of X509 objects
		@param data - contents of the message
		@param cipher - CipherType object
		@param flags - flag
		"""
		# Need to be able to handle OPENSSL stacks
		raise NotImplementedError	
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
