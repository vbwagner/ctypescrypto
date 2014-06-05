ctypescrypto
============

Python interface to some openssl function based on ctypes module

This module is based on works from

http://code.google.com/p/ctypescrypto/

It is aimed to provide Python interface to OpenSSL libcrypto function

Now supported:

bio.py - interfase to OpenSSL stream abstraction BIO. Now supports
	memory BIOs this module intended to use for parsing/serializing
	various ASN.1 based formats like private keys or certificates
	Status: bare minimum functionality is implemented and covered by
	rests

oid.py - interface to OpenSSL ASN.1 Object Identifier databsase.
	Allows to convert numeric identifier (NIDs) returned by various
	OpenSSL function to readable names or dotted-decimal OIDs and back
	Status: Fully implemented and covered by tests.

engine.py - interface to loadable modules with alternate implementations
    of cryptoalgorithms.
	Status: Bare minumum, neccessary to use GOST algorithms is
	implemented.

rand.py - interface to pseudo-random number generator.
	Status: Implemented. Tests now only ensure that no segfault occurs
	if arugments are passed correctly

digests.py  - Interface  to EVP\_Digest\* family of functions. 
	Really does almost same as hashlib, which even is able to take
	advantage of loaded engines if compiled against dynamic libcrypto
	Status: fully implemented and covered by tests

ciphers.py - Interface to EVP\_Cipher family of function. 
	Status: Needs documenting and test coverage

pkey.py - Low-level private key operations (like pkey, genpkey and p
    keyutl command line ops), all via algorithm-agnostic EVP interface.
	Status: Designed and started to implement but not yet covered by tests

exception.py OpenSSL error stack to python exception conversion
	Implemented.

x509 X509 certificates. Support parsing of X509 certificates,
	verification and extracting of field values. Possible extnesion -
	support creattion of PKCS10 certificate requests.
	Status: Interface designed and partially implemented

