from ctypescrypto.oid import Oid,create,cleanup
import unittest

class TestStandard(unittest.TestCase):
    def test_cn(self):
        o=Oid("2.5.4.3")
        self.assertEqual(repr(o),"Oid('2.5.4.3')")
        self.assertEqual(o.dotted(),"2.5.4.3")
        self.assertEqual(str(o),"2.5.4.3")
        self.assertEqual(o.shortname(),"CN")
        self.assertEqual(o.longname(),"commonName")
    def test_getnid(self):
        o=Oid("2.5.4.3")
        x=Oid("CN")
        self.assertEqual(o.nid,x.nid)
        self.assertEqual(o,x)
        self.assertEqual(hash(o),hash(x))

    def test_cons2(self):
        o=Oid("2.5.4.3")
        x=Oid("commonName")
        self.assertEqual(o.nid,x.nid)
    def test_bynid(self):
        o=Oid("2.5.4.3")
        x=Oid(o.nid)
        self.assertEqual(o.nid,x.nid)
    def test_clone(self):
        o1=Oid('2.5.4.3')
        o2=Oid(o1)
        self.assertEqual(o1.nid,o2.nid)
    def test_fromunicode(self):
        o=Oid(u'commonName')
        self.assertEqual(o.shortname(),'CN')
    def test_wrongoid(self):
        with self.assertRaises(ValueError):
            o=Oid("1.2.3.4.5.6.7.8.10.111.1111")
    def test_wrongname(self):
        with self.assertRaises(ValueError):
            o=Oid("No such oid in the database")
    def test_wrongnid(self):
        with self.assertRaises(ValueError):
            o=Oid(9999999)
    def test_wrongtype(self):
        with self.assertRaises(TypeError):
            o=Oid([2,5,3,4])

class TestCustom(unittest.TestCase):
    def _no_testCreate(self):
        d='1.2.643.9.100.99'
        sn="CtypesCryptoTestOid"
        long_name="Test Oid in CryptoCom namespace"
        o=create(d,sn,long_name)
        self.assertEqual(str(o),d)
        self.assertEqual(o.shortname(),sn)
        self.assertEqual(o.longname(),long_name)
    def testLookup(self):
        d='1.2.643.9.100.99'
        sn="CtypesCryptoTestOid"
        long_name="Test Oid In CryptoCom Namespace"
        o=create(d,sn,long_name)
        x=Oid(sn)
        self.assertEqual(o,x)
    def _no_testFromObj(self):
        from ctypescrypto import libcrypto
        from ctypes import c_int, c_char_p, c_void_p
        libcrypto.OBJ_txt2obj.argtypes = (c_char_p, c_int)
        libcrypto.OBJ_txt2obj.restype = c_void_p
        obj= libcrypto.OBJ_txt2obj("1.2.643.100.9",1)
        oid=Oid.fromobj(obj)
        self.assertEqual(str(oid),'1.2.643.100.9')
    def tearDown(self):
        # Always call cleanup before next test
        cleanup()
    



if __name__ == '__main__':
    unittest.main()
