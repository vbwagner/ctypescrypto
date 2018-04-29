from ctypescrypto.pbkdf2 import pbkdf2
import unittest

class TestPBKDF2(unittest.TestCase):
    answersha1=b'\xc13\xb3\xc8\x80\xc2\t\x01\xdaR]\x08\x03\xaf>\x85\xed\x9bU\xf0\x89\n\x81Ctu\xee\xe3\xfe\xd9\xfd\x85\xe2"\x8c\xfbQ\xfeb4\x8f(ZF\xfd\xc3w\x13'
    answersha256=b'oY\xaf\xf7\xfeB7@\xa80%\t\'\xd5r0\xbe\xb4\xf7\xe6TQ\xd2|Tx\xc0e\xff[0a\xe56\xec\xff\xda\xcd\xed~\xbde\xad"\xe8\t\x01o'
    answersha1_1000=b'\xe9\xfe\xbf\xf5K\xfc\xe6h\xfd\xe3\x01\xac\xc8Uc\xcc\x9d\xc7\x1e\xf6\xf8\xd7\xaa\xef\x06se\xbe\x0e^e"\xefa\xba\xe1\xb0\x0b\xc1;\xcd\x05G<\xcc\rE\xfb'
    def test_defaults(self):
        d=pbkdf2("password",b"saltsalt",48)
        self.assertEqual(d,self.answersha1)
    def test_sha1(self):
        d=pbkdf2("password",b"saltsalt",48,digesttype="sha1",iterations=2000)
        self.assertEqual(d,self.answersha1)
    def test_1000iter(self):
        d=pbkdf2("password",b"saltsalt",48,digesttype="sha1",iterations=1000)
        self.assertEqual(d,self.answersha1_1000)
    def test_sha256(self):  
        d=pbkdf2("password",b"\01\02\03\04\0abc",48,digesttype="sha256")
        self.assertEqual(d,self.answersha256)
        
if __name__ == "__main__":
    unittest.main()
