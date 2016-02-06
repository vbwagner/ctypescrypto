# -*- encoding: utf-8 -*-
"""
This module provides interface to OpenSSL MAC functions.

It has not only HMAC support, but can support other types of MAC.

"""

from ctypescrypto.digest import Digest,DigestType,DigestError
from ctypescrypto.oid import Oid
from ctypescrypto import libcrypto
from ctypes import c_int,c_char_p, c_void_p, c_size_t,POINTER,create_string_buffer,pointer

__all__ = ['MAC','DigestError']
class MAC(Digest):
    """
        This object represents MAC context. It is quite simular
        to digest algorithm. It is simular to hmac objects provided
        by standard library
    """
    def __init__(self,algorithm,key,digest=None,**kwargs):
        """
        Constructor has to obligatory arguments:
            
            @param algorithm - which is name of MAC algorithm i.e 'hmac' or 
                    'gost-mac' or equivalent Oid object
            @param key - byte buffer with key.

        Optional parameters are:
            digest - Oid or name of the digest algorithm to use. If none
                specified, OpenSSL will try to derive one from the MAC
                algorithm (or if algorithm is hmac, we'll substititute md5
                for compatibility with standard hmac module

            any other keyword argument is passed to EVP_PKEY_CTX as string
            option.

        """
        if isinstance(algorithm,str):
            self.algorithm=Oid(algorithm)
        elif isinstance(algorithm,Oid):
            self.algorithm=algorithm
        else:
            raise TypeError("Algorthm must be string or Oid")
        if self.algorithm==Oid('hmac') and digest is None:
                digest='md5'
        self.name=self.algorithm.shortname().lower()
        if digest is not None:
            self.digest_type=DigestType(digest)
            self.name+='-'+self.digest_type.digest_name
            d=self.digest_type.digest
        else:
            self.digest_type=None
            d=None
        self.key=libcrypto.EVP_PKEY_new_mac_key(self.algorithm.nid,None,key,len(key))
        if self.key is None:
            raise DigestError("EVP_PKEY_new_mac_key")
        pctx=c_void_p()
        self.ctx = self.newctx()
        if self.ctx == 0:
            raise DigestError("Unable to create digest context")
        if libcrypto.EVP_DigestSignInit(self.ctx,pointer(pctx),d,None,self.key) <= 0:
            raise DigestError("Unable to intialize digest context")
        self.digest_finalized=False
        if self.digest_type is None:
            self.digest_type=DigestType(Oid(libcrypto.EVP_MD_type(libcrypto.EVP_MD_CTX_md(self.ctx))))
        for (name,val) in kwargs.items():
            if libcrypto.EVP_PKEY_CTX_ctrl_str(pctx,name,val)<=0:
                raise DigestError("Unable to set mac parameter")
        self.digest_size = self.digest_type.digest_size
        self.block_size = self.digest_type.block_size
    def digest(self,data=None):
        """
        Method digest is redefined to return keyed MAC value instead of
        just digest.
        """
        if data is not None:
            self.update(data)
        b=create_string_buffer(256)
        size=c_size_t(256)
        if libcrypto.EVP_DigestSignFinal(self.ctx,b,pointer(size))<=0:
            raise DigestError('SignFinal')
        self.digest_finalized=True
        return b.raw[:size.value]

libcrypto.EVP_DigestSignFinal.argtypes=(c_void_p,c_char_p,POINTER(c_size_t))
libcrypto.EVP_DigestSignFinal.restype=c_int
libcrypto.EVP_DigestSignInit.argtypes=(c_void_p,POINTER(c_void_p),c_void_p,c_void_p,c_void_p)
libcrypto.EVP_DigestSignInit.restype=c_int
libcrypto.EVP_PKEY_CTX_ctrl_str.argtypes=(c_void_p,c_char_p,c_char_p)
libcrypto.EVP_PKEY_CTX_ctrl_str.restype=c_int
libcrypto.EVP_PKEY_new_mac_key.argtypes=(c_int,c_void_p,c_char_p,c_int)
libcrypto.EVP_PKEY_new_mac_key.restype=c_void_p
libcrypto.EVP_MD_CTX_md.argtypes=(c_void_p,)
libcrypto.EVP_MD_CTX_md.restype=c_void_p
