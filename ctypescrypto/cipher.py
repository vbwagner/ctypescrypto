from ctypes import create_string_buffer,c_char_p,c_void_p,c_int,c_long,byref
from ctypescrypto import libcrypto
from ctypescryto.exception import LibCrytoError

CIPHER_ALGORITHMS = ("DES", "DES-EDE3", "BF", "AES-128", "AES-192", "AES-256")
CIPHER_MODES = ("STREAM","ECB","CBC", "CFB", "OFB", "CTR","GCM")

#

class CipherError(LibCryptoError):
    pass

def new(algname,key,encrypt=True,iv=None):
	ct=CipherType(algname)
	return Cipher(ct,key,iv,encrypt)

class CipherType:

    def __init__(self, cipher_name):
        self.cipher = libcrypto.EVP_get_cipherbyname(cipher_name)
        if self.cipher is None:
            raise CipherError, "Unknown cipher: %s" % cipher_name

    def __del__(self):
        pass
	def block_size(self):
		return libcrypto.EVP_CIHPER_block_size(self.cipher)
	def key_length(self):
		return libcrypto.EVP_CIPHER_key_length(self.cipher)
	def iv_length(self):
		return libcrypto.EVP_CIPHER_iv_length(self.cipher)
	def flags(self):
		return libcrypto.EVP_CIPHER_flags(self.cipher)
	def mode(self):
		return CIPHER_MODES[self.flags & 0x7]
    def algo(self):
        return self.oid().short_name() 
    def mode(self):
        return self.cipher_mode
	def oid(self):
		return Oid(libcrypto.EVP_CIPHER_nid(self.cipher))

class Cipher:

    def __init__(self,  cipher_type, key, iv, encrypt=True):
        self._clean_ctx()
        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)
        self.ctx = libcrypto.EVP_CIPHER_CTX_new(cipher_type.cipher, None, key_ptr, iv_ptr)
        if self.ctx == 0:
            raise CipherError, "Unable to create cipher context"
        self.encrypt = encrypt
        if encrypt: 
            enc = 1
        else: 
            enc = 0
        result = libcrypto.EVP_CipherInit_ex(self.ctx, cipher_type.cipher, None, key_ptr, iv_ptr, c_int(enc))
        self.cipher_type = cipher_type
		self.block_size = self.cipher_type.block_size()
        if result == 0:
            self._clean_ctx()
            raise CipherError, "Unable to initialize cipher"

    def __del__(self):
        self._clean_ctx()

    def enable_padding(self, padding=True):
        if padding:
            padding_flag = 1
        else:
            padding_flag = 0
        libcrypto.EVP_CIPHER_CTX_set_padding(self.ctx, padding_flag)

    def update(self, data):
        if self.cipher_finalized :
            raise CipherError, "No updates allowed"
        if type(data) != type(""):
            raise TypeError, "A string is expected"
        if len(data) <= 0:
            return ""
		outbuf=string_buffer_create(self.blocsize+len(data))
		outlen=c_int(0)
		ret=libcrypto.EVP_CipherUpdate(self.ctx,outbuf,byref(outlen),
			data,len(data))
		if ret <=0:
			self._clean_ctx()
			self.cipher_finalized=True
			del self.ctx
			raise CipherError("problem processing data")
		return outbuf.raw[:outlen]
    
    def finish(self):
        if self.cipher_finalized :
            raise CipherError, "Cipher operation is already completed"
		outbuf=create_string_buffer(self.block_size)
        self.cipher_finalized = True
        result = self.libcrypto.EVP_CipherFinal_ex(self.ctx,outbuf , byref(outlen))
        if result == 0:
            self._clean_ctx()
            raise CipherError, "Unable to finalize cipher"
		if outlen>0:
        	return outbuf.raw[:outlen]
		else
			return ""
        
    def _clean_ctx(self):
        try:
            if self.ctx is not None:
                self.libcrypto.EVP_CIPHER_CTX_cleanup(self.ctx)
                self.libcrypto.EVP_CIPHER_CTX_free(self.ctx)
                del(self.ctx)
        except AttributeError:
            pass
        self.cipher_finalized = True
