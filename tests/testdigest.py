from ctypescrypto.oid import Oid
from ctypescrypto import digest
from base64 import b16decode,b16encode
import unittest

class TestDigestType(unittest.TestCase):
    def test_md4(self):
        d=digest.DigestType("md4")
        self.assertEqual(d.digest_size,16)
        self.assertEqual(d.block_size,64)
        self.assertEqual(d.oid,Oid("md4"))
        self.assertEqual(d.name,'md4')
    def test_md5(self):
        d=digest.DigestType("md5")
        self.assertEqual(d.digest_size,16)
        self.assertEqual(d.block_size,64)
        self.assertEqual(d.oid,Oid("md5"))
        self.assertEqual(d.name,'md5')
    def test_sha1(self):
        d=digest.DigestType("sha1")
        self.assertEqual(d.digest_size,20)
        self.assertEqual(d.block_size,64)
        self.assertEqual(d.oid,Oid("sha1"))
        self.assertEqual(d.name,'sha1')
    def test_sha256(self):
        d=digest.DigestType("sha256")
        self.assertEqual(d.digest_size,32)
        self.assertEqual(d.block_size,64)
        self.assertEqual(d.oid,Oid("sha256"))
        self.assertEqual(d.name,'sha256')
    def test_sha384(self):
        d=digest.DigestType("sha384")
        self.assertEqual(d.digest_size,48)
        self.assertEqual(d.block_size,128)
        self.assertEqual(d.oid,Oid("sha384"))
        self.assertEqual(d.name,'sha384')
    def test_sha512(self):
        d=digest.DigestType("sha512")
        self.assertEqual(d.digest_size,64)
        self.assertEqual(d.block_size,128)
        self.assertEqual(d.oid,Oid("sha512"))
        self.assertEqual(d.name,'sha512')
    def test_createfromoid(self):
        oid=Oid('sha256')
        d=digest.DigestType(oid)
        self.assertEqual(d.digest_size,32)
        self.assertEqual(d.block_size,64)
        self.assertEqual(d.oid,Oid("sha256"))
        self.assertEqual(d.name,'sha256')
    def test_createfromEVP_MD(self):
        d1=digest.DigestType("sha256")
        d2=digest.DigestType(None)
        with self.assertRaises(AttributeError):
            s=d2.name
        d2.digest=d1.digest
        self.assertEqual(d2.digest_size,32)
        self.assertEqual(d2.block_size,64)
        self.assertEqual(d2.oid,Oid("sha256"))
        self.assertEqual(d2.name,'sha256')
    def test_invalidDigest(self):
        with self.assertRaises(digest.DigestError):
            d=digest.DigestType("no-such-digest")


class TestIface(unittest.TestCase):
    """ Test all methods with one algorithms """
    msg=b"A quick brown fox jumps over the lazy dog."
    dgst="00CFFE7312BF9CA73584F24BDF7DF1D028340397"
    def test_cons(self):
        md=digest.DigestType("sha1")
        dgst=digest.Digest(md)
        dgst.update(self.msg)
        self.assertEqual(dgst.digest_size,20)
        self.assertEqual(dgst.hexdigest(),self.dgst)
    def test_digestwithdata(self):
        md=digest.DigestType("sha1")
        dgst=digest.Digest(md)
        self.assertEqual(dgst.digest(self.msg),b16decode(self.dgst))
    def test_length(self):
        l=len(self.msg)
        msg=self.msg+b" Dog barks furiously."
        dgst=digest.new("sha1")
        dgst.update(msg,length=l)
        self.assertEqual(dgst.hexdigest(),self.dgst)
    def test_badlength(self):
        l=len(self.msg)
        dgst=digest.new("sha1")
        with self.assertRaises(ValueError):
            dgst.update(self.msg,length=l+1)
    def test_bindigest(self):
        dgst=digest.new("sha1")
        dgst.update(self.msg)
        self.assertEqual(dgst.digest_size,20)
        self.assertEqual(dgst.digest(),b16decode(self.dgst,True)) 
    def test_duplicatedigest(self):
        dgst=digest.new("sha1")
        dgst.update(self.msg)
        v1=dgst.digest()
        v2=dgst.digest()
        self.assertEqual(v1,v2)
    def test_updatefinalized(self):
        dgst=digest.new("sha1")
        dgst.update(self.msg)
        h=dgst.hexdigest()
        with self.assertRaises(digest.DigestError):
            dgst.update(self.msg)
    def test_wrongtype(self):
        dgst=digest.new("sha1")
        with self.assertRaises(TypeError):
            dgst.update(['a','b','c'])
        with self.assertRaises(TypeError):
            dgst.update(18)
        with self.assertRaises(TypeError):
            dgst.update({"a":"b","c":"D"})
        with self.assertRaises(TypeError):
            dgst.update(u'\u0430\u0431')
    def test_copy(self):
        dgst=digest.new("sha1")
        dgst.update(b"A quick brown fox jumps over ")
        d2=dgst.copy()
        dgst.update(b"the lazy dog.")
        value1=dgst.hexdigest()
        d2.update(b"the fat pig.")
        value2=d2.hexdigest()
        self.assertEqual(value1,"00CFFE7312BF9CA73584F24BDF7DF1D028340397")
        self.assertEqual(value2,"5328F33739BEC2A15B6A30F17D3BC13CC11A7C78")
class TestAlgo(unittest.TestCase):
    """ Test all statdard algorithms """
    def test_md5(self):
        d=digest.new("md5")
        self.assertEqual(d.digest_size,16)
        d.update(b"A quick brown fox jumps over the lazy dog.")
        self.assertEqual(d.hexdigest(),"DF756A3769FCAB0A261880957590C768")

    def test_md4(self):
        d=digest.new("md4")
        d.update(b"A quick brown fox jumps over the lazy dog.")
        self.assertEqual(d.digest_size,16)
        self.assertEqual(d.hexdigest(),"FAAED595A3E38BBF0D9B4B98021D200F")
    def test_sha256(self):
        d=digest.new("sha256")
        d.update(b"A quick brown fox jumps over the lazy dog.")
        self.assertEqual(d.digest_size,32)
        self.assertEqual(d.hexdigest(),"FFCA2587CFD4846E4CB975B503C9EB940F94566AA394E8BD571458B9DA5097D5")
    def test_sha384(self):
        d=digest.new("sha384")
        d.update(b"A quick brown fox jumps over the lazy dog.")
        self.assertEqual(d.digest_size,48)
        self.assertEqual(d.hexdigest(),"C7D71B1BA81D0DD028E79C7E75CF2F83169C14BA732CA5A2AD731151584E9DE843C1A314077D62B96B03367F72E126D8")
    def test_sha512(self):
        d=digest.new("sha512")
        self.assertEqual(d.digest_size,64)
        d.update(b"A quick brown fox jumps over the lazy dog.")
        self.assertEqual(d.hexdigest(),"3045575CF3B873DD656F5F3426E04A4ACD11950BB2538772EE14867002B408E21FF18EF7F7B2CAB484A3C1C0BE3F8ACC4AED536A427353C7748DC365FC1A8646")
    def test_wrongdigest(self):
        with self.assertRaises(digest.DigestError):
            dgst=digest.new("no-such-digest")

if __name__ == "__main__":
    unittest.main()
