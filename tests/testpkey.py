from ctypescrypto.pkey import PKey
from ctypescrypto import pyver
import unittest,re
from base64 import b64decode, b16decode
from subprocess import Popen,PIPE,CalledProcessError

def pem2der(s):
    start=s.find('-----\n')
    finish=s.rfind('\n-----END')
    data=s[start+6:finish]
    return b64decode(data)

def runopenssl(args,indata):
    p=Popen(['openssl']+args,stdin=PIPE,stdout=PIPE,stderr=PIPE)
    (out,err)=p.communicate(indata)
    if p.returncode:
        raise CalledProcessError(p.returncode," ".join(['openssl']+args)+":"+err)
    if pyver > 2:
        out = out.decode("utf-8")
    return out


class TestPKey(unittest.TestCase):
    rsa="""-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAL9CzVZu9bczTmB8
776pPUoPo6WbAfwQqqiGrj91bk2mYE+MNLo4yIQH45IcwGzkyS8+YyQJf8Bux5BC
oZ2nwzXm5+JZkxkN1mtMzit2D7/hHmrZLoSbr0sxXFrD4a35RI4hXnSK9Sk01sXA
Te2OgHzm5nk1sG97G6SFq7CHe3gvAgMBAAECgYAgGV8K7Y5xk7vIt88oyZCOuHc3
mP9JRabOp+PgpJ3BjHXHg/lpc5Q7jHNmF0s4O2GEe0z6RFnbevwlOvmS0xAQ1hpg
5TnVVkiZvcJeQaZqWIlEOaLqA12YdhSyorfB6p3tfQ7ZmQusg3SCsru5kPJV4sm0
I+MuRCQZWSzIqelloQJBAPbtScJI0lXx8sktntZi69cAVvLtz5z1T7bZwFakNkNE
SUCjNc/hEEI6/1LScV8Kx9kgQ0+W8smu+GyUDceyVFECQQDGSeS7cTmojkiPQxPB
zb0vS+Nfpq6oYsx+gn5TBgMeWIZZrtMEaUU2o+rwsjKBP/gy6D1zC2b4W5O/A/7a
1GR/AkBUQhYoKKc1UpExGtMXfrvRKrmAvatZeM/Rqi4aooAtpfCFEOw82iStJOqY
/VxYPRqCuaKeVvjT31O/4SlumihxAkBahRU0NKYbuoiJThfQ23lIBB7SZadKG4A7
KJs+j3oQ+lyqyFJwqxX7sazpIJBJzMgjhT24LTZenn++LbbEcz1FAkBmDmxoq7qO
Ao6uTm8fnkD4C836wS4mYAPqwRBK1JvnEXEQee9irf+ip89BAg74ViTcGF9lwJwQ
gOM+X5Db+3pK
-----END PRIVATE KEY-----
"""
    rsaenc="""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,7FF0E46291D60D35ACA881131C244655

BeJoui1lRQDvvPr+gH8xCdqkcgKCLWpZTvFZmvrqXmPqMHpm20nK0ESAd6kKm8d1
zaglRIHnnO6V7aDcwgOd3IYPEOnG2TIRQniZrwZdrXIfacscJ6Ekq+5YfLuyrRgq
fscGl7ntm/eGLqwrhzuv7jAXpn9QWiiAld0EWcmZCAW7nGaUQtu4rc4ULwL5SC/M
MOCPwpcD3SCQv55dX3cBOtfZ3lPbpgEpTpnNnj8OtxOkkIaG8yol7luwHvoOSyL/
WuXGCpfJE4LzbxnSLhbiN7q+y/Sro3cGc9aO4tXToMqTFel4zqR0YgOeFazlDRi1
mPuZcGLuSIef0kJn7Mg7jt0DQk579rTVxAhIu2rylTwEozkpCp5g4kGTJON++HQr
BRrApm4XlAoH2GX1jqDBoWSnXCRH49jNGQrLwy469i+994cG8uVU9Z5cqm/LDIR9
kwQfTJIvMi0g28NBMVgJ2gLj40OczxDGyNvBIbhPNswHljfsvPVr4vtxDGx8fS0N
lUJUOL9me+XNZ5xGHYuT5DOr7GE+H3hKEg+XfrYEete9BeI4gm9cqESvrLY9EU5Q
tOtnKKL7SglTZ5LxPMAedADC0o01nzr+D3gAiOhSgoZTrnQsSZ7iTJOtm3vNXwJx
AgesYmXtr5mdiBPKQ1QA/jF5LUZji+5KENd5WHNQw7tOlMLDrPFVRfLZg1AQDljx
u16kdyb71Kk3f6GCOfUntGr+kzppc3DDT+RcLetXphOOEQRy6C6/wmz08WlAPlu5
mFfSDijpWxoUHooQISg5mE82oR8V81aBpbLtm7KevwY=
-----END RSA PRIVATE KEY-----
"""
    pkcs8crypt="""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICoTAbBgkqhkiG9w0BBQMwDgQIipVEnsV/gQoCAggABIICgE1i42C4aBhykhOi
EItFRE+9iBgiklGxoCJtukdp1UwDRKy/GJJ1rcS385CQy4Rs0zN8NH1faVRbf4Vt
iNACHtJx30qMCdo64CR+GJYHS4g2lGaz7PFNma8SjnAbGYXwXkdm5zhwmiU++wC7
W59u8oWS8Dj9dZBMzoOQGQT6xzZwQ14H65zHvC16HdKSNtRgXDWkBnD2cQzuOyuf
rFLyEf7/FH6B7/yKDcwsEfu97uPPxMvuusD1UubWnltO/Hc2oCPibN+dGw1PY9mC
18yGQtZkf5z30yhLosF62IVy3XY9Yf/TJYojIExoASrThGRvENzWkQ3qfnErqmng
l+dy66bmLjicobF5bO3xAhpU1dL+4/1ba2QuthVNlg6Or/iII1ntNN4PFyYcEwmX
e09C3dyOtV7qCq13S1bRkbZhzwi2QbLKALAzrZpF6VYmayTz8KjQOZ8BncAM+BiI
CtwuZJoXLW9kT4D7UsaSZdjUvzBIak5qdCGWpKmahMfjEEsCg6ApuIYmFrCgiY9c
0keYjY8DJ+4bEvqsQvTIaU9F9mFytI1E3LnR0NP1jHuOA7Jc+oNQ2adgFNj12jKQ
qNt1bEGNCqQHSrw7JNCrB7s+QAFNqJtno6fIq7vVNkqadJlnBbCIgm7NlJeGg9j6
a5YVNGlbs0J4dQF4Jw13302IBn3piSzthWL2gL98v/1lEwGuernEpPAjry3YhzM9
VA/oVt22n3yVA6dOSVL1oUTJyawEqASmH0jHAzXNDz+QLSLmz82ARcZPqPvVc45e
5h0xtqtFVkQLNbYzpNWGrx7R1hdr84nOKa8EsIxTRgEL/w9Y4Z/3xEoK2+KVBpMk
oxUuxuU=
-----END ENCRYPTED PRIVATE KEY-----
"""
    password="1111"
    rsakeytext="""Public-Key: (1024 bit)
Modulus:
    00:bf:42:cd:56:6e:f5:b7:33:4e:60:7c:ef:be:a9:
    3d:4a:0f:a3:a5:9b:01:fc:10:aa:a8:86:ae:3f:75:
    6e:4d:a6:60:4f:8c:34:ba:38:c8:84:07:e3:92:1c:
    c0:6c:e4:c9:2f:3e:63:24:09:7f:c0:6e:c7:90:42:
    a1:9d:a7:c3:35:e6:e7:e2:59:93:19:0d:d6:6b:4c:
    ce:2b:76:0f:bf:e1:1e:6a:d9:2e:84:9b:af:4b:31:
    5c:5a:c3:e1:ad:f9:44:8e:21:5e:74:8a:f5:29:34:
    d6:c5:c0:4d:ed:8e:80:7c:e6:e6:79:35:b0:6f:7b:
    1b:a4:85:ab:b0:87:7b:78:2f
Exponent: 65537 (0x10001)
"""
    ec1priv="""-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgKnG6neqZvB98EEuuxnHs
fv+L/5abuNNG20wzUqRpncOhRANCAARWKXWeUZ6WiCKZ2kHx87jmJyx0G3ZB1iQC
+Gp2AJYswbQPhGPigKolzIbZYfwnn7QOca6N8QDhPAn3QQK8trZI
-----END PRIVATE KEY-----
"""
    ec1keytext="""Public-Key: (256 bit)
pub:
    04:56:29:75:9e:51:9e:96:88:22:99:da:41:f1:f3:
    b8:e6:27:2c:74:1b:76:41:d6:24:02:f8:6a:76:00:
    96:2c:c1:b4:0f:84:63:e2:80:aa:25:cc:86:d9:61:
    fc:27:9f:b4:0e:71:ae:8d:f1:00:e1:3c:09:f7:41:
    02:bc:b6:b6:48
ASN1 OID: secp256k1
"""
    ec1pub="""-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEVil1nlGelogimdpB8fO45icsdBt2QdYk
AvhqdgCWLMG0D4Rj4oCqJcyG2WH8J5+0DnGujfEA4TwJ90ECvLa2SA==
-----END PUBLIC KEY-----
"""
    
    def test_unencrypted_pem(self):
        key=PKey(privkey=self.rsa)
        self.assertTrue(key.cansign)
        self.assertIsNotNone(key.key)
        self.assertEqual(str(key),self.rsakeytext)
    def test_encrypted_pem(self):
        key=PKey(privkey=self.rsaenc,password=self.password)
        self.assertIsNotNone(key.key)
        self.assertEqual(str(key),self.rsakeytext)
    def test_encrypted_pem_cb(self):
        cb=lambda x:self.password
        key=PKey(privkey=self.rsaenc,password=cb)
        self.assertIsNotNone(key.key)
        self.assertEqual(str(key),self.rsakeytext)
    def test_encryped_pem_pkcs8(self):
        key=PKey(privkey=self.pkcs8crypt,password=self.password)
        self.assertIsNotNone(key.key)
        self.assertEqual(str(key),self.rsakeytext)
    def test_encrypted_der_pkcs8(self):
        pkcs8der = pem2der(self.pkcs8crypt)
        key=PKey(privkey=pkcs8der,password=self.password,format="DER")
        self.assertIsNotNone(key.key)
        self.assertEqual(str(key),self.rsakeytext)
    def test_export_priv_pem(self):
        key=PKey(privkey=self.ec1priv)
        out=key.exportpriv()
        self.assertEqual(self.ec1priv,out)
    def test_export_priv_encrypt(self):
        from ctypescrypto.cipher import CipherType
        key=PKey(privkey=self.rsa)
        pem=key.exportpriv(password='2222',cipher=CipherType("aes256"))
        if pyver >2:
            pem = pem.encode("ascii")
        self.assertEqual(runopenssl(["pkey","-text_pub","-noout","-passin","pass:2222"],
                                    pem),self.rsakeytext)
    def test_export_priv_der(self):
        key=PKey(privkey=self.rsa)
        der=key.exportpriv(format="DER")
        self.assertEqual(runopenssl(["pkey","-text_pub","-noout","-inform","DER"],
            der),self.rsakeytext)
    def test_export_priv_der_enc(self):
        from ctypescrypto.cipher import CipherType
        key=PKey(privkey=self.rsa)
        der=key.exportpriv(format="DER",password='2222',cipher=CipherType("aes256"))
        self.assertEqual(runopenssl(["pkcs8","-passin","pass:2222","-inform","DER"],
            der),self.rsa)
    def test_unencrypted_pem_ec(self):
        
        key=PKey(privkey=self.ec1priv)
        self.assertIsNotNone(key.key)
        self.assertEqual(re.sub("pub: \n","pub:\n",str(key)),self.ec1keytext)
    def test_unencrypted_der_ec(self):
        key=PKey(privkey=pem2der(self.ec1priv),format="DER")
        self.assertIsNotNone(key.key)
        self.assertEqual(re.sub("pub: \n","pub:\n",str(key)),self.ec1keytext)
    def test_pubkey_pem(self):
        key=PKey(pubkey=self.ec1pub)
        self.assertIsNotNone(key.key)   
        self.assertEqual(re.sub("pub: \n","pub:\n",str(key)),self.ec1keytext)
    def test_pubkey_der(self):
        key=PKey(pubkey=pem2der(self.ec1pub),format="DER")
        self.assertIsNotNone(key.key)   
        self.assertEqual(re.sub("pub: \n","pub:\n",str(key)),self.ec1keytext)
    def test_compare(self):
        key1=PKey(privkey=self.ec1priv)
        self.assertIsNotNone(key1.key)
        key2=PKey(pubkey=self.ec1pub)
        self.assertIsNotNone(key2.key)
        self.assertEqual(key1,key2)
    def test_sign(self):
        signer=PKey(privkey=self.ec1priv)
        digest=b16decode("FFCA2587CFD4846E4CB975B503C9EB940F94566AA394E8BD571458B9DA5097D5")
        signature=signer.sign(digest)
        self.assertTrue(len(signature)>0)
        verifier=PKey(pubkey=self.ec1pub)
        self.assertTrue(verifier.verify(digest,signature))
    def test_generate(self):
        newkey=PKey.generate("rsa")
        self.assertIsNotNone(newkey.key)
        s=str(newkey)
        self.assertEqual(s[:s.find("\n")],"Public-Key: (1024 bit)")
    def test_generate_params(self):
        newkey=PKey.generate("rsa",rsa_keygen_bits=2048)
        self.assertIsNotNone(newkey.key)
        s=str(newkey)
        self.assertEqual(s[:s.find("\n")],"Public-Key: (2048 bit)")
    def test_generate_ec(self):
        templkey=PKey(pubkey=self.ec1pub)
        newkey=PKey.generate("ec",paramsfrom=templkey)
        self.assertIsNotNone(newkey.key)
        s=str(newkey)
        self.assertEqual(s[:s.find("\n")],"Public-Key: (256 bit)")
        self.assertNotEqual(str(templkey),str(newkey))
if __name__ == "__main__":
    unittest.main()
