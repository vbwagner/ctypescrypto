# -*- encoding: utf-8 -*-
from ctypescrypto.oid import Oid
from base64 import b16decode,b16encode
from ctypescrypto.mac import *
from ctypescrypto.engine import set_default
import unittest

class TestMac(unittest.TestCase):
    def test_hmac_default(self):
        d=MAC('hmac',key=b'1234'*4)
        d.update(b'The Quick brown fox jumps over the lazy dog\n')
        self.assertEqual(d.name,'hmac-md5')
        self.assertEqual(d.hexdigest(),'A9C16D91CDF2A99273B72336D0D16B56')
    def test_hmac_digestdataa(self):
        d=MAC('hmac',key=b'1234'*4)
        h=d.hexdigest(b'The Quick brown fox jumps over the lazy dog\n')
        self.assertEqual(d.name,'hmac-md5')
        self.assertEqual(h,'A9C16D91CDF2A99273B72336D0D16B56')
    def test_hmac_byoid(self):
        d=MAC(Oid('hmac'),key=b'1234'*4)
        d.update(b'The Quick brown fox jumps over the lazy dog\n')
        self.assertEqual(d.name,'hmac-md5')
        self.assertEqual(d.hexdigest(),'A9C16D91CDF2A99273B72336D0D16B56')
    def test_mac_wrongtype(self):
        with self.assertRaises(TypeError):
            d=MAC(Oid('hmac').nid,key=b'1234'*4)
    def test_hmac_sha256(self):
        d=MAC('hmac',key=b'1234'*16,digest='sha256')
        d.update(b'The Quick brown fox jumps over the lazy dog\n')
        self.assertEqual(d.name,'hmac-sha256')
        self.assertEqual(d.hexdigest(),'BEBA086E1C67200664DCDEEC697D99DB1A8DAA72933A36B708FC5FD568173095')
    def test_gostmac(self):
        set_default('gost')
        d=MAC('gost-mac',key=b'1234'*8)
        d.update(b'The Quick brown fox jumps over the lazy dog\n')
        self.assertEqual(d.name,'gost-mac')
        self.assertEqual(d.digest_size,4)
        self.assertEqual(d.hexdigest(),'76F25AE3')
        with self.assertRaisesRegexp(DigestError,"invalid mac key length"):
            d=MAC('gost-mac',key=b'1234'*4)

if __name__ == "__main__":
    unittest.main()
