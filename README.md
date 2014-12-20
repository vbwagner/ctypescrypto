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

Possible future enhancements
----------------------------

1. Creation and signing of the certificate requests (PKCS#10)
2. Parsing and analyzing CRLs
3. OCSP ([RFC 6960](http://tools.ietf.org/html/rfc6960))request creation and response parsing
4. Timestamping ([RFC 3161](http://tools.ietf.org/html/rfc3161))
support.
6. MAC support. Few people know that there is more MACs than just HMAC,
and even fewer, that OpenSSL supports them.
