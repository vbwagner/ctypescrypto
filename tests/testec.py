from ctypescrypto.oid import Oid
from ctypescrypto.ec import create
from base64 import b16decode
import unittest



class TestEcCreation(unittest.TestCase):
    ec1priv="""-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgKnG6neqZvB98EEuuxnHs
fv+L/5abuNNG20wzUqRpncOhRANCAARWKXWeUZ6WiCKZ2kHx87jmJyx0G3ZB1iQC
+Gp2AJYswbQPhGPigKolzIbZYfwnn7QOca6N8QDhPAn3QQK8trZI
-----END PRIVATE KEY-----
"""
    bigkey="""-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgAAAAAAAAAAAAAAAAAAAA
AUVRIxlQt1/EQC2hcy/Jvr6hRANCAASRZsKJufkF5V+ePfn2nX81a0oiCV+JT0cV
cUqktWYGr/GB65Zr5Ky1z/nha2bYCb6U4hTwbJP9CRCZr5hJklXn
-----END PRIVATE KEY-----
"""
    def test_keyone(self):
        key=create(Oid("secp256k1"),b16decode("2A71BA9DEA99BC1F7C104BAEC671EC7EFF8BFF969BB8D346DB4C3352A4699DC3",True))
            
        out=key.exportpriv()
        self.assertEqual(out,self.ec1priv)

    def test_bignum(self):
        keyval='\xff'*32
        key=create(Oid("secp256k1"),keyval)
        self.assertEqual(key.exportpriv(),self.bigkey)
if __name__ == "__main__":
    unittest.main()
