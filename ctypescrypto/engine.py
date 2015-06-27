"""
engine loading and configuration
"""
from ctypes import c_void_p, c_char_p, c_int
from ctypescrypto import libcrypto
from ctypescrypto.exception import LibCryptoError

__all__ = ['default', 'set_default']

default = None

def set_default(engine):
    """
    Loads specified engine and sets it as default for all
    algorithms, supported by it
    """
    global default
    eng = libcrypto.ENGINE_by_id(engine)
    if eng is None:
        # Try load engine
        eng = libcrypto.ENGINE_by_id("dynamic")
        if  eng is None:
            raise LibCryptoError("Cannot get 'dynamic' engine")
        if not libcrypto.ENGINE_ctrl_cmd_string(eng, "SO_PATH", engine, 0):
            raise LibCryptoError("Cannot execute ctrl cmd SO_PATH")
        if not libcrypto.ENGINE_ctrl_cmd_string(eng, "LOAD", None, 0):
            raise LibCryptoError("Cannot execute ctrl cmd LOAD")
    if eng is None:
        raise ValueError("Cannot find engine " + engine)
    libcrypto.ENGINE_set_default(eng, c_int(0xFFFF))
    default = eng

# Declare function result and arguments for used functions
libcrypto.ENGINE_by_id.restype = c_void_p
libcrypto.ENGINE_by_id.argtypes = (c_char_p, )
libcrypto.ENGINE_set_default.argtypes = (c_void_p, c_int)
libcrypto.ENGINE_ctrl_cmd_string.argtypes = (c_void_p, c_char_p, c_char_p,
                                             c_int)
libcrypto.ENGINE_finish.argtypes = (c_char_p, )
