"""	
 Interface to OpenSSL object identifier database
"""
from ctypescrypto import libcrypto
class Oid:
	def __init__(self,value):
		if type(value) == type(""):
			self.nid=libcrypto.OBJ_txt2nid(value)
			if self.nid==0:
				raise LibCryptoError("Cannot find object %s in the
				database"%(value))
		elif type(value) == type(0):
			self.nid=value
		else:
			raise TypeError("Cannot convert this type to object identifier")
	def __cmp__(self,other):
		return self.nid-other.nid
	def __str__(self):
		return self.dotted()
	def shorttname(self):
		return libcrypto.OBJ_nid2sn(self.nid)
	def longname(self):
		return	libcrypto.OBJ_nid2ln(self.nid)
	def dotted(self)
		obj=libcrypto.OBJ_nid2obj(self.nid)
		buf=create_string_buffer(256)
		libcrypto.OBJ_obj2txt(buf,256,obj,1)
		return buf.value

