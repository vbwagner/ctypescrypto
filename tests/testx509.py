#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from ctypescrypto.x509 import X509,X509Store,utc,StackOfX509
from ctypescrypto.oid import Oid
from tempfile import NamedTemporaryFile
import datetime
import unittest
import os



class TestCertInfo(unittest.TestCase):
    ca_cert="""-----BEGIN CERTIFICATE-----
MIIEDzCCAvegAwIBAgIJAN9Ejmna3JJ7MA0GCSqGSIb3DQEBBQUAMIGdMQswCQYD
VQQGEwJSVTEVMBMGA1UECAwM0JzQvtGB0LrQstCwMTAwLgYDVQQKDCfQo9C00L7R
gdGC0L7QstC10YDRj9GO0YnQuNC5INGG0LXQvdGC0YAxIjAgBgNVBAMMGdCS0LjQ
utGC0L7RgCDQktCw0LPQvdC10YAxITAfBgkqhkiG9w0BCQEWEnZpdHVzQHdhZ25l
ci5wcC5ydTAeFw0xNDEwMjYxNDQ2MzJaFw0xNzEwMjUxNDQ2MzJaMIGdMQswCQYD
VQQGEwJSVTEVMBMGA1UECAwM0JzQvtGB0LrQstCwMTAwLgYDVQQKDCfQo9C00L7R
gdGC0L7QstC10YDRj9GO0YnQuNC5INGG0LXQvdGC0YAxIjAgBgNVBAMMGdCS0LjQ
utGC0L7RgCDQktCw0LPQvdC10YAxITAfBgkqhkiG9w0BCQEWEnZpdHVzQHdhZ25l
ci5wcC5ydTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJn+nL8CDaM0
KNafGYdEDuFuCKHFxCcbaT7ecGbwjPKtnqZLOnYpa2iLFY+n7zAYw1MRkFkaR8b+
+AeFPWS9T60ygeWysT9XTS77Fdl69Tmr8HChRk0BuLB3vFCy34vBHSG6Frdm8PtS
PLEleldiwUCHLS+EckrnJylQK13X3HofSbIGzKK53MsuQOtp2dJw3b7MILM/+XBm
RgZlEbTEPYMOH8CE3mu9/LqXfIRQM7+nmzcNZI3RAwxEVHOSHEbgFZaksTj8rMIa
SrJwknmxHntI3P5PSNNbs0SO3TW8ePDIIpbVcjNsMX4qGX8b+8quZuzciKOto8S0
0A6eOBd8Vi0CAwEAAaNQME4wHQYDVR0OBBYEFKzcbd6+N1TKfBjvmyTvw8+DnzAZ
MB8GA1UdIwQYMBaAFKzcbd6+N1TKfBjvmyTvw8+DnzAZMAwGA1UdEwQFMAMBAf8w
DQYJKoZIhvcNAQEFBQADggEBAAa1PpkpL842hh8jLXIpA/nK8aVDDcu5p3pA72/b
noFnZuKcuaSUOz1rrLqxDK2JB3lmChQaVx3pZwqJgA0h0XBScar+8wM2TfeyW+oU
Gr5tOAxoHVRpgn6oCoJkKo0HS2/NA12T/gYsXhXJXn4tuvDjaUzY+K+hhAWh64oL
/c61eKfCZKp50t9Eoua0xHII2Mveb27Ps46j/CZ1r0ts7sGieOqjQo3GZOOikG6F
vFY/2KV16/FdBovTFWMyKrzlYHm0Wgt28IWqhocq/golLfvkz3VAkLQvOF2i6hNc
4feBv69SRTsTCFN9PtJCtxPX/K9LZKeccBKgGjrHQpAF+JU=
-----END CERTIFICATE-----
"""
    cert1="""-----BEGIN CERTIFICATE-----
MIIEDzCCAvegAwIBAgIJAN9Ejmna3JJ8MA0GCSqGSIb3DQEBBQUAMIGdMQswCQYD
VQQGEwJSVTEVMBMGA1UECAwM0JzQvtGB0LrQstCwMTAwLgYDVQQKDCfQo9C00L7R
gdGC0L7QstC10YDRj9GO0YnQuNC5INGG0LXQvdGC0YAxIjAgBgNVBAMMGdCS0LjQ
utGC0L7RgCDQktCw0LPQvdC10YAxITAfBgkqhkiG9w0BCQEWEnZpdHVzQHdhZ25l
ci5wcC5ydTAeFw0xNDEwMjYxOTA3MTdaFw0yNDEwMjMxOTA3MTdaMIGBMQswCQYD
VQQGEwJSVTEVMBMGA1UECAwM0JzQvtGB0LrQstCwMRUwEwYDVQQHDAzQnNC+0YHQ
utCy0LAxIDAeBgNVBAoMF9Cn0LDRgdGC0L3QvtC1INC70LjRhtC+MSIwIAYDVQQD
DBnQktC40LrRgtC+0YAg0JLQsNCz0L3QtdGAMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEArQSfrrxNROyzNEz60G2EHBP+E4BL0b1QytGAZZiQp2XIhhQe
b7mx+c4mpwgvD7/IdAcK+YVGx78nfY723T3wG48U7HzFNbLvNDycxyXecXbvCmRs
xPy8TxkwPf6TIT3UcixtwMMqZFqlAtSTDmOOWSaUuftL/+yFk729xDoYkOZhFwUS
UM5SbEZ0JpufWFjDi3Qwj3ZOTXliHC3e4C7187Me0Nne59dttyKpq1YAThn4Srar
vZYU6Ykk/LUae0FCvfeiKLShWY05XnPVmvPiiFTXJP8/Au8kfezlA4b+eS81zWq2
BFvNlBQsgf04S88oew0CuBBgtjUIIw7XZkS03QIDAQABo2wwajAJBgNVHRMEAjAA
MB0GA1UdDgQWBBRflZBerCFYheRQne/sWL3zY7GiAzAfBgNVHSMEGDAWgBSs3G3e
vjdUynwY75sk78PPg58wGTAdBgNVHREEFjAUgRJ2aXR1c0B3YWduZXIucHAucnUw
DQYJKoZIhvcNAQEFBQADggEBAGx1z0ylq90hP3x/2DmfVUYBA46CiGnV4NSiaOWE
Y18jCuG3W8FcI7JP4uEEjKyz3XbuhTFW2GsZ2L3FGgpA5eXBikgCn5kRpOHgb45r
SxE8u3TwVlYlaF+7RHPYLqmgb25d/O/28McemMmTGecPC9edbtDqLv03aJ0t4gXn
BD+xTJOP74Yhu5IPIV92J6pSBpIoy+qiyOA1iRpOWzrVHVR504vAaFxlfZs3VJhP
uo291iEXyooazJdbWwZwcwk7WrNNKhqktPTg0X1ZHNnGwOAGPzwNJFGPeFj71r0t
aFWU5EMRKaZK75keXq/RdaOAenl+nKF6xA2XHDhGgdndFfY=
-----END CERTIFICATE-----
"""
    pubkey1="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArQSfrrxNROyzNEz60G2E
HBP+E4BL0b1QytGAZZiQp2XIhhQeb7mx+c4mpwgvD7/IdAcK+YVGx78nfY723T3w
G48U7HzFNbLvNDycxyXecXbvCmRsxPy8TxkwPf6TIT3UcixtwMMqZFqlAtSTDmOO
WSaUuftL/+yFk729xDoYkOZhFwUSUM5SbEZ0JpufWFjDi3Qwj3ZOTXliHC3e4C71
87Me0Nne59dttyKpq1YAThn4SrarvZYU6Ykk/LUae0FCvfeiKLShWY05XnPVmvPi
iFTXJP8/Au8kfezlA4b+eS81zWq2BFvNlBQsgf04S88oew0CuBBgtjUIIw7XZkS0
3QIDAQAB
-----END PUBLIC KEY-----
"""
    digicert_cert="""digicert.crt
-----BEGIN CERTIFICATE-----
MIIG5jCCBc6gAwIBAgIQAze5KDR8YKauxa2xIX84YDANBgkqhkiG9w0BAQUFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTA3MTEwOTEyMDAwMFoXDTIxMTExMDAwMDAwMFowaTEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTEoMCYGA1UEAxMfRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug
RVYgQ0EtMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPOWYth1bhn/
PzR8SU8xfg0ETpmB4rOFVZEwscCvcLssqOcYqj9495BoUoYBiJfiOwZlkKq9ZXbC
7L4QWzd4g2B1Rca9dKq2n6Q6AVAXxDlpufFP74LByvNK28yeUE9NQKM6kOeGZrzw
PnYoTNF1gJ5qNRQ1A57bDIzCKK1Qss72kaPDpQpYSfZ1RGy6+c7pqzoC4E3zrOJ6
4GAiBTyC01Li85xH+DvYskuTVkq/cKs+6WjIHY9YHSpNXic9rQpZL1oRIEDZaARo
LfTAhAsKG3jf7RpY3PtBWm1r8u0c7lwytlzs16YDMqbo3rcoJ1mIgP97rYlY1R4U
pPKwcNSgPqcCAwEAAaOCA4UwggOBMA4GA1UdDwEB/wQEAwIBhjA7BgNVHSUENDAy
BggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUH
AwgwggHEBgNVHSAEggG7MIIBtzCCAbMGCWCGSAGG/WwCATCCAaQwOgYIKwYBBQUH
AgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5o
dG0wggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0
AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1
AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABp
AGcAaQBDAGUAcgB0ACAARQBWACAAQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBl
AGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBo
AGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAg
AGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAg
AGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wEgYDVR0TAQH/BAgwBgEB/wIBADCB
gwYIKwYBBQUHAQEEdzB1MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
dC5jb20wTQYIKwYBBQUHMAKGQWh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NBQ2Vy
dHMvRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3J0MIGPBgNVHR8EgYcw
gYQwQKA+oDyGOmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hB
c3N1cmFuY2VFVlJvb3RDQS5jcmwwQKA+oDyGOmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0
LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJvb3RDQS5jcmwwHQYDVR0OBBYE
FExYyyXwQU9S9CjIgUObpqig5pLlMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoI
Au9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQBMeheHKF0XvLIyc7/NLvVYMR3wsXFU
nNabZ5PbLwM+Fm8eA8lThKNWYB54lBuiqG+jpItSkdfdXJW777UWSemlQk808kf/
roF/E1S3IMRwFcuBCoHLdFfcnN8kpCkMGPAc5K4HM+zxST5Vz25PDVR708noFUjU
xbvcNRx3RQdIRYW9135TuMAW2ZXNi419yWBP0aKb49Aw1rRzNubS+QOy46T15bg+
BEkAui6mSnKDcp33C4ypieez12Qf1uNgywPE3IjpnSUBAHHLA7QpYCWP+UbRe3Gu
zVMSW4SOwg/H7ZMZ2cn6j1g0djIvruFQFGHUqFijyDATI+/GJYw2jxyA
-----END CERTIFICATE-----
"""
    def test_readpubkey(self):
        c=X509(self.cert1)
        p=c.pubkey
        self.assertEqual(p.exportpub(),self.pubkey1)
    def test_pem(self):
        c=X509(self.cert1)
        self.assertEqual(c.pem(),self.cert1)
    def test_subject(self):
        c=X509(self.cert1)
        self.assertEqual(unicode(c.subject),u'C=RU,ST=Москва,L=Москва,O=Частное лицо,CN=Виктор Вагнер')
    def test_subject_str(self):
        c=X509(self.cert1)
        self.assertEqual(str(c.subject),b'C=RU,ST=\\D0\\9C\\D0\\BE\\D1\\81\\D0\\BA\\D0\\B2\\D0\\B0,L=\\D0\\9C\\D0\\BE\\D1\\81\\D0\\BA\\D0\\B2\\D0\\B0,O=\\D0\\A7\\D0\\B0\\D1\\81\\D1\\82\\D0\\BD\\D0\\BE\\D0\\B5 \\D0\\BB\\D0\\B8\\D1\\86\\D0\\BE,CN=\\D0\\92\\D0\\B8\\D0\\BA\\D1\\82\\D0\\BE\\D1\\80 \\D0\\92\\D0\\B0\\D0\\B3\\D0\\BD\\D0\\B5\\D1\\80')
    def test_subject_len(self):
        c=X509(self.cert1)
        self.assertEqual(len(c.subject),5)
    def test_issuer(self):
        c=X509(self.cert1)
        self.assertEqual(unicode(c.issuer),u'C=RU,ST=Москва,O=Удостоверяющий центр,CN=Виктор Вагнер,emailAddress=vitus@wagner.pp.ru')
    def test_subjectfields(self):
        c=X509(self.cert1)
        self.assertEqual(c.subject[Oid("C")],"RU")
        with self.assertRaises(TypeError):
            x=c.subject["CN"]
        self.assertEqual(c.subject[Oid("L")],u'\u041c\u043e\u0441\u043a\u0432\u0430')
    def test_subjectmodify(self):
        c=X509(self.cert1)
        with self.assertRaises(ValueError):
            c.subject[Oid("CN")]=u'Foo'
        with self.assertRaises(ValueError):
            del c.subject[Oid('CN')]
    def test_subjectbadsubfield(self):
        c=X509(self.cert1)
        with self.assertRaises(KeyError):
            x=c.subject[Oid("streetAddress")]
    def test_subjectfieldindex(self):
        c=X509(self.cert1)
        self.assertEqual(repr(c.subject[0]),repr((Oid('C'),u'RU')))
    def test_subjectbadindex(self):
        c=X509(self.cert1)
        with self.assertRaises(IndexError):
            x=c.subject[11]
        with self.assertRaises(IndexError):
            x=c.subject[-1]
    def test_notBefore(self):
        c=X509(self.cert1)
        self.assertEqual(c.startDate,datetime.datetime(2014,10,26,19,07,17,0,utc))
    def test_notAfter(self):
        c=X509(self.cert1)
        self.assertEqual(c.endDate,datetime.datetime(2024,10,23,19,7,17,0,utc))
    def test_subjectHash(self):
        c=X509(self.cert1)
        self.assertEqual(hash(c.subject),0x1f3ed722)
    def test_issuerHash(self):
        c=X509(self.cert1)
        self.assertEqual(hash(c.issuer),0x7d3ea8c3)
    def test_namecomp(self):
        c=X509(self.cert1)
        ca=X509(self.ca_cert)
        self.assertEqual(c.issuer,ca.subject)
        self.assertNotEqual(c.subject,c.issuer)
        self.assertEqual(ca.issuer,ca.subject)
    def test_serial(self):
        c=X509(self.cert1)
        self.assertEqual(c.serial,0xDF448E69DADC927CL)
    def test_version(self):
        c=X509(self.cert1)
        self.assertEqual(c.version,3)
    def test_ca_cert(self):
        ca=X509(self.ca_cert)
        self.assertTrue(ca.check_ca())
        notca=X509(self.cert1)
        self.assertFalse(notca.check_ca())
    def test_extension_count(self):
        cert=X509(self.cert1)
        self.assertTrue(len(cert.extensions),4)
        ca_cert=X509(self.ca_cert)
        self.assertEqual(len(ca_cert.extensions),3)
    def test_extension_outofrange(self):
        cert=X509(self.cert1)
        with self.assertRaises(IndexError):
            cert.extensions[4]
        with self.assertRaises(IndexError):
            cert.extensions[-1]
    def test_extension_oid(self):
        cert=X509(self.cert1)
        ext=cert.extensions[0]
        ext_id=ext.oid
        self.assertTrue(isinstance(ext_id,Oid))
        self.assertEqual(ext_id,Oid('basicConstraints'))
    def test_extension_text(self):
        cert=X509(self.cert1)
        ext=cert.extensions[0]
        self.assertEqual(str(ext),'CA:FALSE')
        self.assertEqual(unicode(ext),u'CA:FALSE')
    def test_extenson_find(self):
        cert=X509(self.cert1)
        exts=cert.extensions.find(Oid('subjectAltName'))
        self.assertEqual(len(exts),1)
        self.assertEqual(exts[0].oid,Oid('subjectAltName'))
    def test_extension_bad_find(self):
        cert=X509(self.cert1)
        with self.assertRaises(TypeError):
            exts=cert.extensions.find('subjectAltName')
    def test_extenson_critical(self):
        cert=X509(self.digicert_cert)
        crit_exts=cert.extensions.find_critical()
        self.assertEqual(len(crit_exts),2)
        other_exts=cert.extensions.find_critical(False)
        self.assertEqual(len(crit_exts)+len(other_exts),len(cert.extensions))
        self.assertEqual(crit_exts[0].critical,True)
        self.assertEqual(other_exts[0].critical,False)
    def test_verify_by_key(self):
        ca=X509(self.ca_cert)
        pubkey=ca.pubkey
        self.assertTrue(ca.verify(key=pubkey))
        c=X509(self.cert1)
        pk2=c.pubkey
        self.assertFalse(c.verify(key=pk2))
        self.assertTrue(c.verify(key=pubkey))
    def test_verify_self_singed(self):
        ca=X509(self.ca_cert)
        self.assertTrue(ca.verify())
    def test_default_filestore(self):
        store=X509Store(default=True)
        c1=X509(self.cert1)
        # Cert signed by our CA shouldn't be successfully verified
        # by default CA store
        self.assertFalse(c1.verify(store))
        # but cert, downloaded from some commercial CA - should.
        c2=X509(self.digicert_cert)
        self.assertTrue(c2.verify(store))
    def test_verify_by_filestore(self):
        trusted=NamedTemporaryFile(delete=False)
        trusted.write(self.ca_cert)
        trusted.close()
        goodcert=X509(self.cert1)
        badcert=X509(self.cert1[0:-30]+"GG"+self.cert1[-28:])
        gitcert=X509(self.digicert_cert)
        store=X509Store(file=trusted.name)
        os.unlink(trusted.name)
        # We should successfuly verify certificate signed by our CA cert
        self.assertTrue(goodcert.verify(store))
        # We should reject corrupted certificate
        self.assertFalse(badcert.verify(store))
        # And if we specify explicitely certificate file, certificate,
        # signed by some commercial CA should be rejected too
        self.assertFalse(gitcert.verify(store))
        trusted.close()
    def test_verify_by_dirstore(self):
        pass
    def test_certstack1(self):
        l=[]
        l.append(X509(self.cert1))
        self.assertEqual(unicode(l[0].subject[Oid('CN')]),u'Виктор Вагнер')
        l.append(X509(self.ca_cert))
        l.append(X509(self.digicert_cert))
        stack=StackOfX509(certs=l)
        self.assertEqual(len(stack),3)
        self.assertTrue(isinstance(stack[1],X509))
        self.assertEqual(unicode(stack[0].subject[Oid('CN')]),u'Виктор Вагнер')
        with self.assertRaises(IndexError):
            c=stack[-1]
        with self.assertRaises(IndexError):
            c=stack[3]
        del stack[1]
        self.assertEqual(len(stack),2)
        self.assertEqual(unicode(stack[0].subject[Oid('CN')]),u'Виктор Вагнер')
        self.assertEqual(unicode(stack[1].subject[Oid('CN')]),u'DigiCert High Assurance EV CA-1')
    def test_certstack2(self):
        stack=StackOfX509()
        stack.append(X509(self.cert1))
        stack.append(X509(self.ca_cert))
        c=stack[1]
        stack[1]=X509(self.digicert_cert)
        self.assertEqual(len(stack),2)
        self.assertEqual(unicode(stack[1].subject[Oid('CN')]),u'DigiCert High Assurance EV CA-1')
        with self.assertRaises(IndexError):
            stack[-1]=c
        with self.assertRaises(IndexError):
            stack[3]=c
        with self.assertRaises(TypeError):
            stack[0]=self.cert1
        with self.assertRaises(TypeError):
            stack.append(self.cert1)
    def test_certstack3(self):
        l=[]
        l.append(X509(self.cert1))
        self.assertEqual(unicode(l[0].subject[Oid('CN')]),u'Виктор Вагнер')
        l.append(X509(self.ca_cert))
        l.append(X509(self.digicert_cert))
        stack=StackOfX509(certs=l)
        stack2=StackOfX509(ptr=stack.ptr,disposable=False)
        with self.assertRaises(ValueError):
            stack3=StackOfX509(ptr=stack.ptr,certs=l)
        with self.assertRaises(ValueError):
            stack2[1]=l[0]
        with self.assertRaises(ValueError):
            stack2.append(l[0])
if __name__ == '__main__':
    unittest.main()
