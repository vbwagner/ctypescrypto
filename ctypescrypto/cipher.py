from ctypes import *

CIPHER_ALGORITHMS = ("DES", "DES-EDE3", "BF", "AES-128", "AES-192", "AES-256")
CIPHER_MODES = ("CBC", "CFB", "OFB", "ECB")

class CipherError(Exception):
    pass

class CipherType:

    def __init__(self, libcrypto, cipher_algo, cipher_mode):
        self.libcrypto = libcrypto
        self.cipher_algo = cipher_algo
        self.cipher_mode = cipher_mode
        cipher_name = "-".join([self.cipher_algo, self.cipher_mode])
        self.cipher = self.libcrypto.EVP_get_cipherbyname(cipher_name)
        if self.cipher == 0:
            raise CipherError, "Unknown cipher: %s" % cipher_name

    def __del__(self):
        pass

    def algo(self):
        return self.cipher_algo

    def mode(self):
        return self.cipher_mode

class Cipher:

    def __init__(self, libcrypto, cipher_type, key, iv, encrypt=True):
        self.libcrypto = libcrypto
        self._clean_ctx()
        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)
        self.ctx = self.libcrypto.EVP_CIPHER_CTX_new(cipher_type.cipher, None, key_ptr, iv_ptr)
        if self.ctx == 0:
            raise CipherError, "Unable to create cipher context"
        self.encrypt = encrypt
        if encrypt: 
            enc = 1
        else: 
            enc = 0
        result = self.libcrypto.EVP_CipherInit_ex(self.ctx, cipher_type.cipher, None, key_ptr, iv_ptr, c_int(enc))
        self.cipher_type = cipher_type
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
        self.libcrypto.EVP_CIPHER_CTX_set_padding(self.ctx, padding_flag)

    def update(self, data):
        if self.cipher_finalized :
            raise CipherError, "No updates allowed"
        if type(data) != type(""):
            raise TypeError, "A string is expected"
        if len(data) <= 0:
            return ""
        self.data = self.data + data
    
    def finish(self, data=None):
        if data is not None:
            self.update(data)
        return self._finish()
        
    def _finish(self):
        if self.cipher_finalized :
            raise CipherError, "Cipher operation is already completed"
        self.cipher_out = create_string_buffer(len(self.data) + 32)
        result = self.libcrypto.EVP_CipherUpdate(self.ctx, byref(self.cipher_out), byref(self.cipher_out_len), c_char_p(self.data), len(self.data))
        if result == 0:
            self._clean_ctx()
            raise CipherError, "Unable to update cipher"
        self.cipher_finalized = True
        update_data = self.cipher_out.raw[:self.cipher_out_len.value]
        result = self.libcrypto.EVP_CipherFinal_ex(self.ctx, byref(self.cipher_out), byref(self.cipher_out_len))
        if result == 0:
            self._clean_ctx()
            raise CipherError, "Unable to finalize cipher"
        final_data = self.cipher_out.raw[:self.cipher_out_len.value]
        return update_data + final_data
        
    def _clean_ctx(self):
        try:
            if self.ctx is not None:
                self.libcrypto.EVP_CIPHER_CTX_cleanup(self.ctx)
                self.libcrypto.EVP_CIPHER_CTX_free(self.ctx)
                del(self.ctx)
        except AttributeError:
            pass
        self.cipher_out = None
        self.cipher_out_len = c_long(0)
        self.data = ""
        self.cipher_finalized = False