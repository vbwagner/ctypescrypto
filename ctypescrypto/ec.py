"""
Support for EC keypair operation missing form public libcrypto API
"""


def create(curve,num):
	"""
		Creates EC keypair from the just secret key and curve name
		
		@param curve - name of elliptic curve
		@param num - long number representing key
	"""
	p=libcrypto.EVP_PKEY_new()
	ec=libcrypto.EC_KEY_new_by_curvename(curve.nid)
	group=libcrypto.EC_KEY_get0_group(ec)
	EC_KEY_set_private_key(ec,bn)
	priv_key=libcrypt.BN_new()
	ctx=BN_CTX_new()
	h="%x"%(num)
	libcrypto.BN_hex2bn(byref(priv_key),h)
	libcrypto.EC_KEY_set_private_key(ec,priv_key)
	pub_key=libcrypto.EC_POINT_new(group)
	libcrypto.EC_POINT_mul(group,pub_key,priv_key,None,None,ctx)
	libcrypto.BN_free(a)
	libcrypto.EVP_PKEY_set1_EC_KEY(p,ec)
	libcrypto.EC_KEY_free(ec)
	return PKey(ptr=p,cansign=True)


libcrypto.EVP_PKEY_new.restype=c_void_p
libcrypto.BN_new.restype=c_void_p
libcrypto.BN_hex2bn.argtypes(POINTER(c_void_p),c_char_p)
libcrypto.EC_KEY_set_private_key
