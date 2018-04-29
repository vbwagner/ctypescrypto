ctypescrypto
============

Python interface to some openssl function based on ctypes module

This module is based on works from

http://code.google.com/p/ctypescrypto/

most recent version can be checked out from

https://github.com/vbwagner/ctypescrypto.git

Rationale
---------

Why have yet another crypto extension for Python? There is pyopenssl,
m2crypto, hashlib in the standard library and many more.

But most of these extension implement interfaces to particular set of
cryptoalgorthms. This extension takes an another approach — it uses
algorithm-agnostic EVP layer whenever possible, and so support any
algorithms which are supported by underlying library, even this
algorithms are implemented in the loadable modules (engines). Algorithms
which you've just added to library, should be supported too.

Also, this extension takes some care of correctly converting textual
information from ASN.1 structures into unicode.


Digest calculation
------------------

Module **ctypescrypto.digest** contain **new()** function which produces
objects simular to python **hashlib** module objects. 

On the systems where hashlib is linked with libcrypto dynamically,
hashlib even able to make use of digest types, provided by loadable
engines. 

This module would utilize same copy of libcrypto library as other
ctypescrypto modules, so it would work with engine-provided digests.

Additionally there is **DigestType** class which may be needed to
construct CMS SignedData objects or add signatures to them.


MAC calculation
---------------

Mac is Message Authentication Code - it is like keyed digest, which
depends not only on message, but also on key, which should be used both
when initially computing MAC and when verifying it. MACs can be viewed
as "digital signatures with symmetric keys".

Most common type of MAC is HMAC (i.e. hash-based MAC), described in 
[RFC 2104](https://tools.ietf.org/html/rfc2104), but there are other,
for instance [GOST 28147-89](https://tools.ietf.org/html/rfc5830) defines MAC based on symmetric cipher.
Also GSM 0348 uses DES symmetric cipher as MAC. OpenSSL supports
GOST mac via loadable engine module, but doesn't seem to support any
non-HMAC MAC in the core. So, MAC is only test in the test suite which
requires loadable engine.

Symmetric ciphers
-----------------

Module *ctypescrypto.cipher* contain *new()* function which provides
way to create cipher objects. Cipher padding can be configure later.
This object provides methods *update* and *finish* which allows to
encrypt/decrypt data. All ciphers, supported by your version of OpenSSL
and its loadable engines are supported.

Additionally the **CipherType** class instances may be used directly to
pass to other functions such as CMS EnvelopedData or EncryptedData
**create**

Public key operations
---------------------

Module **ctypescrypto.pkey** provides **PKey** object, which represents
public/private key pair or just public key. With this object you can
sign data, derive shared key and verify signatures.

This is quite low-level object, which can be used to implement some
non-standard protocols and operations.

It is possible to extract public key from the certificate as PKey
object (see below).

Additional module **ctypescrypto.ec** allows to create **PKey** objects
with elliptic curve keys from just raw secret key as byte buffer or
python big integer.

X509 certificates
-----------------

Certificates are cryptographically signed documents, which tie together
public key and some attributes of key owner (certificate subject).
Certificates are signed by some trusted organizations called Certificate
Authorities (one which have issued given certificate, is called
certificate issuer). Your browser or operating system typically have
predefined store of the trusted CA certificates (although nothing
prevent you from running your own CA using openssl command line utility,
and trust only it). 



Certificates are described in [RFC 5280](http://tools.ietf.org/html/rfc5280)

Module **ctypescrypto.x509** contains objects **X509** which represents
certificate (and can be constructed from string, contained PEM
or DER certificate) and object **X509Store** which is a store of trusted
CA certificates which can be used to high-level signature verifications
(i.e. in PKCS7/CMS messages).

There is no support for creating and signing certificates, i.e. to
perform Certificate Authority functions. This library for now focuses on
cryptography user functionality. 

Certificate has properties corresponding to its subject and issuer
names, public key (of course it is PKey object described above) and
serial number. Subject and issuer names can be indexed by OIDs or by
position of field. Unicode in the names is supported.

Support for visualising certificate extensions is minimal for now.
Extension object can be converted into string, extension Oid can be
retrieved and critical flag is checked.

**StackOfX509** implements collection of certificates, necessary for
some operations with CMS and certificate verification.

CMS documents
-------------

CMS stands for Cryptographic Message Syntax. It is defined in the
[RFC 5652](http://tools.ietf.org/html/rfc5652).
CMS defines several types of documents. There is **SignedData**,
which can be read by anyone, but is protected from authorized changes
by digital signature of its author. There is **EnvelopedData** protected
from unauthorized reading by cipher and allowed to be read only by
owners of certain private keys, and there is **EncryptedData**, which
are protected by symmetric cipher keys.


There is basic factory function **CMS()**, which parses PEM or der
representation of cryptographic message and generates appropriate
object. There are **SignedData**, **EnvelopedData** and
**EncryptedData** classes. Each class has static method **create**
allowing to create this subtype of message from raw data and appropriate
keys and certificates.

**SignedData** has **verify()** method. **EnvelopedData** and
**EncryptedData** - **decrypt** method.

Unfortunately, **SignedAndEnvelopedData** seems to be unsupported in
libcrypto as of version 1.0.1 of OpenSSL.

PBKDF2
------

Provides interface to password based key derivation function
Interface slightly differs from the **hashlib.pbkdf2_hmac** function,
which have appeared in Python 2.7.8 but functionality is just same,
although OpenSSL implementation might be faster.



OID database
------------

OpenSSL contains internal object identifiers (OID) database. Each OID
have apart from dotted-decimal representation long name, short name and
numeric identifier. Module **ctypescrypto.oid** provides interface to the
database. **Oid** objects store numeric identifier internally and can
return both long and short name and dotted-decimal representation.

BIO library
-----------

OpenSSL contain BIO (basic input-output) abstraction. And all object
serialization/deserialization use this library. Also human-readable
representation of  ASN.1 structures use this library extensively. So,
we've to develop python object which allow to read from python string
via BIO abstraction or write to buffer, which can be returned as python
string or unicode object. 

Exceptions
----------

Exceptions, used in the **ctypescrypto** to report problems are tied
closely with OpenSSL error-reporting functions, so if such an exception
occurs, as much as possibly information from inside libcrypto would be
available in the Python

Engine support
--------------

There is just one function **ctypescrypt.engine.set_default**, which loads 
specified engine by id and makes it default for all algorithms,
supported by it. It is enough for me to use Russian national
cryptographic algorithms, provided by **gost** engine.

Test Suite
----------

Tests can be run using

    python setup.py test

Test suite is fairly incomplete. Contributions are welcome.

Note that you need properly installed OpenSSL library with set of CA
certificates in the certs directory, otherwise default certstore test
would fail.

You also need gost engine to be available (check with 

   openssl engine gost

) otherwise mac test would crash with error. Unfortunately there is no
non-HMAC MAC in the openssl core, so GOST MAC is only option.

OpenSSL 1.0 includes GOST engine by default. For OpenSSL 1.1 and above
GOST engine is developed as separate project and can be downloaded from
[https://github.com/gost-engine/engine](https://github.com/gost-engine/engine)
Debian buster and above includes gost engine as
libengine-gost-openssl1.1 package.


Possible future enhancements
----------------------------

1. Creation and signing of the certificate requests (PKCS#10)
2. Parsing and analyzing CRLs
3. OCSP ([RFC 6960](http://tools.ietf.org/html/rfc6960))request creation and response parsing
4. Timestamping ([RFC 3161](http://tools.ietf.org/html/rfc3161))
support.

  vim: spelllang=en tw=72
