ctypescrypto
============

Python interface to some openssl function based on ctypes module

This module is based on works from

http://code.google.com/p/ctypescrypto/

It is aimed to provide Python interface to OpenSSL libcrypto function

Now supported:

Digests
Ciphers
Low-level private key operations (like pkey and pkeyutl command line ops)
(all via algorithm-agnostic EVP interface).
Engine loading
OpenSSL error stack to python exception conversion
X509 certificates partially

