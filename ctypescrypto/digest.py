"""
	Implements interface to OpenSSL EVP_Digest* functions.

	Interface  made as close to hashlib as possible.

	This module is really an excess effort. Hashlib allows access to
	mostly same functionality except oids and nids of hashing
	algortithms (which might be needed for private key operations).

	hashlib even allows to use engine-provided digests if it is build
	with dinamically linked libcrypto - so use
	ctypescrypto.engine.set_default("gost",xFFFF) and md_gost94
	algorithm would be available both to this module and hashlib.

"""
from ctypes import c_int, c_char_p, c_void_p, POINTER, c_long,c_longlong, create_string_buffer,byref
from ctypescrypto import libcrypto
from ctypescrypto.exception import LibCryptoError
from ctypescrypto.oid import Oid
DIGEST_ALGORITHMS = ("MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512")


class DigestError(LibCryptoError):
	pass

def new(algname):
	"""
		Behaves just like hashlib.new. Creates digest object by
		algorithm name
	"""
	md=DigestType(algname)
	return Digest(md)

class DigestType:
	"""
		
		Represents EVP_MD object - constant structure which describes
		digest algorithm

	"""
	def __init__(self,	digest_name):
		"""
			Finds digest by its name
		"""
		self.digest_name = digest_name
		self.digest = libcrypto.EVP_get_digestbyname(self.digest_name)
		if self.digest is None:
			raise DigestError, "Unknown digest: %s" % self.digest_name

	def __del__(self):
		pass
	def digest_size(self):
		return libcrypto.EVP_MD_size(self.digest)
	def block_size(self):
		return libcrypto.EVP_MD_block_size(self.digest)
	def oid(self):
		return Oid(libcrypto.EVP_MD_type(self.digest))

class Digest:
	"""
		Represents EVP_MD_CTX object which actually used to calculate
		digests.

	"""
	def __init__(self,digest_type):
		"""
			Initializes digest using given type.
		"""
		self._clean_ctx()
		self.ctx = libcrypto.EVP_MD_CTX_create()
		if self.ctx == 0:
			raise DigestError, "Unable to create digest context"
		result = libcrypto.EVP_DigestInit_ex(self.ctx, digest_type.digest, None)
		if result == 0:
			self._clean_ctx()
			raise DigestError, "Unable to initialize digest"
		self.digest_type = digest_type
		self.digest_size = self.digest_type.digest_size()
		self.block_size = self.digest_type.block_size()

	def __del__(self):
		self._clean_ctx()

	def update(self, data):
		"""
			Hashes given byte string as data
		"""
		if self.digest_finalized:
			raise DigestError, "No updates allowed"
		if type(data) != type(""):
			raise TypeError, "A string is expected"
		result = libcrypto.EVP_DigestUpdate(self.ctx, c_char_p(data), len(data))
		if result != 1:
			raise DigestError, "Unable to update digest"
		
	def digest(self, data=None):
		"""
			Finalizes digest operation and return digest value
			Optionally hashes more data before finalizing
		"""
		if self.digest_finalized:
			return self.digest_out.raw[:self.digest_size]
		if data is not None:
			self.update(data)
		self.digest_out = create_string_buffer(256)
		length = c_long(0)
		result = libcrypto.EVP_DigestFinal_ex(self.ctx, self.digest_out, byref(length))
		if result != 1 :
			raise DigestError, "Unable to finalize digest"
		self.digest_finalized = True
		return self.digest_out.raw[:self.digest_size]
	def copy(self):
		"""
			Creates copy of the digest CTX to allow to compute digest
			while being able to hash more data
		"""
		new_digest=Digest(self.digest_type)
		libcrypto.EVP_MD_CTX_copy(new_digest.ctx,self.ctx)
		return new_digest

	def _clean_ctx(self):
		try:
			if self.ctx is not None:
				libcrypto.EVP_MD_CTX_destroy(self.ctx)
				del(self.ctx)
		except AttributeError:
			pass
		self.digest_out = None
		self.digest_finalized = False

	def hexdigest(self,data=None):
		"""
			Returns digest in the hexadecimal form. For compatibility
			with hashlib
		"""
		from base64 import b16encode
		return b16encode(self.digest(data))


# Declare function result and argument types
libcrypto.EVP_get_digestbyname.restype = c_void_p
libcrypto.EVP_get_digestbyname.argtypes = (c_char_p,)
libcrypto.EVP_MD_CTX_create.restype = c_void_p
libcrypto.EVP_DigestInit_ex.argtypes = (c_void_p,c_void_p,c_void_p)
libcrypto.EVP_DigestUpdate.argtypes = (c_void_p,c_char_p,c_longlong)
libcrypto.EVP_DigestFinal_ex.argtypes = (c_void_p,c_char_p,POINTER(c_long))
libcrypto.EVP_MD_CTX_destroy.argtypes = (c_void_p,)
libcrypto.EVP_MD_CTX_copy.argtypes=(c_void_p, c_void_p)
libcrypto.EVP_MD_type.argtypes=(c_void_p,)
libcrypto.EVP_MD_size.argtypes=(c_void_p,)
libcrypto.EVP_MD_block_size.argtypes=(c_void_p,)
