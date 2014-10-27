ctypescrypto
============

Python interface to some openssl function based on ctypes module

This module is based on works from

http://code.google.com/p/ctypescrypto/

most recent version can be checked out from

https://github.com/vbwagner/ctypescrypto.git

It is aimed to provide Python interface to OpenSSL libcrypto functions.
All the objects in this library are just wrappers around some OpenSSL
data structures and groups of functions.



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

Certificate has properties corresponding to its subject and issuer
names, public key (of course it is PKey object described above) and
serial number. Subject and issuer names can be indexed by OIDs or by
position of field. Unicode in the names is supported.

There is no support for certificate validity time yet.

**StackOfX509** implements collection of certificates, neccessary for
some operations with CMS and certificate verification.

CMS documents
-------------

There is basic constructor function **CMS()**, which parses PEM or der
representation of cryptographic message and generates appropriate
object. There are **SignedData**, **EnvelopedData** and
**EncryptedData** clases. Each class has static method **create**
allowing to create this subtype of message from raw data and appropriate
keys and certificates.

**SignedData** has **verify()** method. **EnvelopedData** and
**EncryptedData** - **decrypt** method.

Unfortunatly, **SignedAndEnvelopedData** seems to be unsupported in
libcrypto as of version 1.0.1 of OpenSSL.

PBKDF2
------

Provices interface to password based keyderivation function
Interface slightly differs from the **hashlib.pbkdf2_hmac** function,
which have appeared in Python 2.7.8 but functionality is just same,
although OpenSSL implementation might be faster.




OID database
------------

OpenSSL conteins internal object identifiers (OID) database. Each OID
have apart from dotted-decimal representation long name, short name and
numeric identifer. Module **ctypescrypto.oid** provides interface to the
database. **Oid** objects store numeric identifier internally and can
return both long and short name and dotted-decimal representation.

BIO library
-----------

OpenSSL contain BIO (basic input-output) abstraction. And all object
serialization/deserialization use this library. Also human-readble
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

There is just one function **ctypescrypt.engine.set_default**. which loads 
specified engine by id and makes it default for all algorithms,
supported by it. It is enough for me to use Russian national
cryptographic algoritms, provided by **gost** engine.

