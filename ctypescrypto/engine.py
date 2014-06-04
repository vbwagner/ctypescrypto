from ctypes import *
from ctypescrypto import libcrypto
from ctypescrypto.exception import LibCryptoError
default=None

def set_default(engine):
	global default
	e=libcrypto.ENGINE_by_id(engine)
	if e is None:
		# Try load engine
		e = libcrypto.ENGINE_by_id("dynamic")
		if  e is None:
			raise LibCryptoError("Cannot get 'dynamic' engine")
		if not libcrypto.ENGINE_ctrl_cmd_string(e,"SO_PATH",engine,0):
			raise LibCryptoError("Cannot execute ctrl cmd SO_PATH")
		if not libcrypto.ENGINE_ctrl_cmd_string(e,"LOAD",None,0):
			raise LibCryptoError("Cannot execute ctrl cmd LOAD")
	if e is None:
		raise ValueError("Cannot find engine "+engine)
	libcrypto.ENGINE_set_default(e,c_int(0xFFFF))
	default=e

# Declare function result and arguments for used functions
libcrypto.ENGINE_by_id.restype=c_void_p
libcrypto.ENGINE_by_id.argtypes=(c_char_p,)
libcrypto.ENGINE_set_default.argtypes=(c_void_p,c_int)
libcrypto.ENGINE_ctrl_cmd_string.argtypes=(c_void_p,c_char_p,c_char_p,c_int)
