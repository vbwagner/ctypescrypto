from ctypescrypto import pyver
from ctypescrypto.oid import Oid
from ctypescrypto.ec import create
from base64 import b16decode
from subprocess import Popen, PIPE
import unittest

def dump_key(key):
    """ Convert key into printable form using openssl utility
       Used to compare keys which can be stored in different
       format by different OpenSSL versions
    """
    return Popen(["openssl","pkey","-text","-noout"],stdin=PIPE,stdout=PIPE).communicate(key)[0]

def dump_pub_key(key):
    """ Convert key into printable form using openssl utility
       Used to compare keys which can be stored in different
       format by different OpenSSL versions
    """
    return Popen(["openssl","pkey","-text_pub","-noout"],stdin=PIPE,stdout=PIPE).communicate(key)[0]
class TestEcCreation(unittest.TestCase):
    ec1priv=b"""-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgKnG6neqZvB98EEuuxnHs
fv+L/5abuNNG20wzUqRpncOhRANCAARWKXWeUZ6WiCKZ2kHx87jmJyx0G3ZB1iQC
+Gp2AJYswbQPhGPigKolzIbZYfwnn7QOca6N8QDhPAn3QQK8trZI
-----END PRIVATE KEY-----
"""
    bigkey=b"""-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgAAAAAAAAAAAAAAAAAAAA
AUVRIxlQt1/EQC2hcy/Jvr6hRANCAASRZsKJufkF5V+ePfn2nX81a0oiCV+JT0cV
cUqktWYGr/GB65Zr5Ky1z/nha2bYCb6U4hTwbJP9CRCZr5hJklXn
-----END PRIVATE KEY-----
"""
    def test_keyone(self):
        key=create(Oid("secp256k1"),b16decode("2A71BA9DEA99BC1F7C104BAEC671EC7EFF8BFF969BB8D346DB4C3352A4699DC3",True))
            
        out=key.exportpriv()
        if pyver > 2:
            out=out.encode("ascii")
        self.assertEqual(dump_key(out),dump_key(self.ec1priv))
        if pyver == 2:
            self.assertEqual(str(key),dump_pub_key(self.ec1priv))
        else:    
            self.assertEqual(str(key).encode("ascii"),dump_pub_key(self.ec1priv))

    def test_bignum(self):
        keyval=b'\xff'*32
        key=create(Oid("secp256k1"),keyval)
        keyblob = key.exportpriv()
        if pyver > 2:
            keyblob = keyblob.encode("ascii")
        self.assertEqual(dump_key(keyblob),dump_key(self.bigkey))
        keyblob2 = str(key)
        if pyver > 2:
             keyblob2 = keyblob2.encode('ascii')
        self.assertEqual(keyblob2,dump_pub_key(self.bigkey))
if __name__ == "__main__":
    unittest.main()
