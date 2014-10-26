#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from ctypescrypto.x509 import X509,X509Store
from ctypescrypto.oid import Oid
import unittest



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
	def test_readpubkey(self):
		c=X509(self.cert1)
		p=c.pubkey
		self.assertEqual(p.exportpub(),self.pubkey1)
	def test_subject(self):
		c=X509(self.cert1)
		self.assertEqual(unicode(c.subject),u'C=RU,ST=Москва,L=Москва,O=Частное лицо,CN=Виктор Вагнер')
	def test_issuer(self):
		c=X509(self.cert1)
		self.assertEqual(unicode(c.issuer),u'C=RU,ST=Москва,O=Удостоверяющий центр,CN=Виктор Вагнер,emailAddress=vitus@wagner.pp.ru')
	def test_subjectfields(self):
		c=X509(self.cert1)
		self.assertEqual(c.subject[Oid("C")],"RU")
		self.assertEqual(c.subject[Oid("L")],u'\u041c\u043e\u0441\u043a\u0432\u0430')
	def test_namecomp(self):
		c=X509(self.cert1)
		ca=X509(self.ca_cert)
		self.assertEqual(c.issuer,ca.subject)
		self.assertNotEqual(c.subject,c.issuer)
		self.assertEqual(ca.issuer,ca.subject)
	def test_serial(self):
		c=X509(self.cert1)
		self.assertEqual(c.serial,0xDF448E69DADC927CL)
	def test_ca_cert(self):
		ca=X509(self.ca_cert)
		self.assertTrue(ca.check_ca())
		notca=X509(self.cert1)
		self.assertFalse(notca.check_ca())
	def test_verify_by_key(self):
		ca=X509(self.ca_cert)
		pubkey=ca.pubkey
		self.assertTrue(ca.verify(key=pubkey))
		c=X509(self.cert1)
		pk2=c.pubkey
		self.assertFalse(c.verify(key=pk2))
		self.assertTrue(c.verify(key=pubkey))
	def test_verify_by_filestore(self):
		pass
	def test_verify_by_dirstore(self):
		pass
if __name__ == '__main__':
	unittest.main()
