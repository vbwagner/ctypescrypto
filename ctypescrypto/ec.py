"""
Support for EC keypair operation missing form public libcrypto API
"""
from ctypescrypto.pkey import PKey, PKeyError
from ctypes import c_void_p, c_char_p, c_int, byref, POINTER
from ctypescrypto import libcrypto

__all__ = ['create']

def create(curve, data):
    """
    Creates EC keypair from the just secret key and curve name

    @param curve - name of elliptic curve
    @param num - byte array or long number representing key
    """
    ec_key = libcrypto.EC_KEY_new_by_curve_name(curve.nid)
    if ec_key is None:
        raise PKeyError("EC_KEY_new_by_curvename")
    group = libcrypto.EC_KEY_get0_group(ec_key)
    if group is None:
        raise PKeyError("EC_KEY_get0_group")
    libcrypto.EC_GROUP_set_asn1_flag(group, 1)
    raw_key = libcrypto.BN_new()
    if isinstance(data, int):
        libcrypto.BN_hex2bn(byref(raw_key), hex(data))
    else:
        if raw_key is None:
            raise PKeyError("BN_new")
        if libcrypto.BN_bin2bn(data, len(data), raw_key) is None:
            raise PKeyError("BN_bin2bn")
    ctx = libcrypto.BN_CTX_new()
    if ctx is None:
        raise PKeyError("BN_CTX_new")
    order = libcrypto.BN_new()
    if order is None:
        raise PKeyError("BN_new")
    priv_key = libcrypto.BN_new()
    if priv_key is None:
        raise PKeyError("BN_new")
    if libcrypto.EC_GROUP_get_order(group, order, ctx) <= 0:
        raise PKeyError("EC_GROUP_get_order")
    if libcrypto.BN_nnmod(priv_key, raw_key, order, ctx) <= 0:
        raise PKeyError("BN_nnmod")
    if libcrypto.EC_KEY_set_private_key(ec_key, priv_key) <= 0:
        raise PKeyError("EC_KEY_set_private_key")
    pub_key = libcrypto.EC_POINT_new(group)
    if pub_key is None:
        raise PKeyError("EC_POINT_new")
    if libcrypto.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx) <= 0:
        raise PKeyError("EC_POINT_mul")
    if libcrypto.EC_KEY_set_public_key(ec_key, pub_key) <= 0:
        raise PKeyError("EC_KEY_set_public_key")
    libcrypto.BN_free(raw_key)
    libcrypto.BN_free(order)
    libcrypto.BN_free(priv_key)
    libcrypto.BN_CTX_free(ctx)
    pkey = libcrypto.EVP_PKEY_new()
    if pkey is None:
        raise PKeyError("EVP_PKEY_new")
    if libcrypto.EVP_PKEY_set1_EC_KEY(pkey, ec_key) <= 0:
        raise PKeyError("EVP_PKEY_set1_EC_KEY")
    libcrypto.EC_KEY_free(ec_key)
    return PKey(ptr=pkey, cansign=True)

libcrypto.EVP_PKEY_new.restype = c_void_p
libcrypto.EC_KEY_new_by_curve_name.restype = c_void_p
libcrypto.EC_KEY_new_by_curve_name.argtypes = (c_int,)
libcrypto.BN_new.restype = c_void_p
libcrypto.BN_free.argtypes = (c_void_p, )
libcrypto.BN_hex2bn.argtypes = (POINTER(c_void_p), c_char_p)
libcrypto.BN_bin2bn.argtypes = ( c_char_p, c_int, c_void_p)
libcrypto.BN_bin2bn.restype = c_void_p
libcrypto.BN_CTX_new.restype = c_void_p
libcrypto.BN_CTX_free.argtypes = (c_void_p, )
libcrypto.BN_bin2bn.argtypes = (c_char_p, c_int, c_void_p)
libcrypto.BN_nnmod.restype = c_int
libcrypto.BN_nnmod.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p)
libcrypto.EC_KEY_set_private_key.argtypes = (c_void_p, c_void_p)
libcrypto.EC_POINT_new.argtypes = (c_void_p, )
libcrypto.EC_POINT_new.restype = c_void_p
libcrypto.EC_POINT_mul.argtypes = (c_void_p, c_void_p, c_void_p, c_void_p,
                                   c_void_p, c_void_p)
libcrypto.EC_KEY_set_public_key.argtypes = (c_void_p, c_void_p)
libcrypto.EC_KEY_get0_group.restype = c_void_p
libcrypto.EC_KEY_get0_group.argtypes = (c_void_p,)
libcrypto.EC_KEY_free.argtypes=(c_void_p,)
libcrypto.EVP_PKEY_set1_EC_KEY.argtypes = (c_void_p, c_void_p)
libcrypto.EC_GROUP_set_asn1_flag.argtypes = (c_void_p, c_int)
libcrypto.EC_GROUP_get_order.restype = c_int
libcrypto.EC_GROUP_get_order.argtypes = (c_void_p, c_void_p, c_void_p)
