from ctypescrypto.rand import *
import unittest

class TestRand(unittest.TestCase):
    def test_bytes(self):
        b=bytes(100)
        self.assertEqual(len(b),100)
        b2=bytes(100)
        self.assertNotEqual(b,b2)
    def test_pseudo_bytes(self):
        b=pseudo_bytes(100)
        self.assertEqual(len(b),100)
        b2=pseudo_bytes(100)
        self.assertNotEqual(b,b2)
    def test_seed(self):
        b=b"aaqwrwfsagdsgdsfgdsfgdfsgdsfgdsgfdsfgdsfg"
        seed(b)
        # Check if no segfault here
    def test_entropy(self):
        b=b"aaqwrwfsagdsgdsfgdsfgdfsgdsfgdsgfdsfgdsfg"
        seed(b,2.25)
        # Check if no segfault here
    def test_Status(self):
        i=status()
        self.assertEqual(i,1)

if __name__ == '__main__':
    unittest.main()
