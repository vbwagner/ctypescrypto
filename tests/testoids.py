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
    def testCreate(self):
        d='1.2.643.100.3'
        sn="SNILS"
        long_name="Russian Pension security number"
        o=create(d,sn,long_name)
        self.assertEqual(str(o),d)
        self.assertEqual(o.shortname(),sn)
        self.assertEqual(o.longname(),long_name)
    def testLookup(self):
        d='1.2.643.100.3'
        sn="SNILS"
        long_name="Russian Pension security number"
        o=create(d,sn,long_name)
        x=Oid(sn)
        self.assertEqual(o,x)
    def testCleanup(self):
        d='1.2.643.100.9'
        sn="SNILX"
        long_name="Russian Pension security number"
        o=create(d,sn,long_name)
        cleanup()
        with self.assertRaises(ValueError):
            x=Oid(sn)
    def tearDown(self):
        # Always call cleanup before next test
        cleanup()
    



if __name__ == '__main__':
    unittest.main()
