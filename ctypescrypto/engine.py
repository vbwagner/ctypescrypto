"""
engine loading and configuration
"""
from ctypes import c_void_p, c_char_p, c_int
from ctypescrypto import libcrypto,pyver
from ctypescrypto.exception import LibCryptoError

__all__ = ['default', 'set_default', 'Engine']

default = None

class Engine(object):
    """
    Represents Openssl loadable module (engine).
    Allows to create PKey objects from private keys stored
    in the token, accessed by engine
    """
    def __init__(self, engine_id, **kwargs):
        if pyver > 2 or isinstance(engine_id, unicode):
            engine_id = engine_id.encode('utf-8')
        eng = libcrypto.ENGINE_by_id(engine_id)
        if eng is None:
            # Try load engine
            eng = libcrypto.ENGINE_by_id("dynamic")
            if  eng is None:
                raise LibCryptoError("Cannot get 'dynamic' engine")
            if not libcrypto.ENGINE_ctrl_cmd_string(eng, "SO_PATH",
                                                    engine_id, 0):
                raise LibCryptoError("Cannot execute ctrl cmd SO_PATH")
            if not libcrypto.ENGINE_ctrl_cmd_string(eng, "LOAD", None, 0):
                raise LibCryptoError("Cannot execute ctrl cmd LOAD")
        if eng is None:
            raise ValueError("Cannot find engine " + engine)
        for cmd, value in kwargs.items():
            if not libcrypto.ENGINE_ctrl_cmd_string(eng, cmd, value, 0):
                raise LibCryptoError("Cannot execute ctrl cmd %s" % cmd)
        if not libcrypto.ENGINE_init(eng):
            raise LibCryptoError("Cannot initialize engine")
        self.ptr = eng

    def private_key(self, key_id, ui_method = None, ui_data=None):
        from ctypescrypto.pkey import PKey
        if ui_method is None:
            ui_ptr = libcrypto.UI_OpenSSL()
        else:
            ui_ptr = ui_method.ptr
        pkey = libcrypto.ENGINE_load_private_key(self.ptr, key_id, ui_ptr,
                                                 ui_data)
        if pkey is None:
            raise LibCryptoError("Cannot load private key")
        return PKey(ptr=pkey, cansign=True)

def set_default(eng, algorithms=0xFFFF):
    """
    Sets specified engine  as default for all
    algorithms, supported by it

    For compatibility with 0.2.x if string is passed instead
    of engine, attempts to load engine with this id
    """
    if not isinstance(eng,Engine):
        eng=Engine(eng)
    global default
    libcrypto.ENGINE_set_default(eng.ptr, c_int(algorithms))
    default = eng

# Declare function result and arguments for used functions
libcrypto.ENGINE_by_id.restype = c_void_p
libcrypto.ENGINE_by_id.argtypes = (c_char_p, )
libcrypto.ENGINE_set_default.argtypes = (c_void_p, c_int)
libcrypto.ENGINE_ctrl_cmd_string.argtypes = (c_void_p, c_char_p, c_char_p,
                                             c_int)
libcrypto.ENGINE_finish.argtypes = (c_char_p, )
libcrypto.ENGINE_init.argtypes = (c_void_p, )
libcrypto.UI_OpenSSL.restype = c_void_p
libcrypto.ENGINE_load_private_key.argtypes = (c_void_p, c_char_p, c_void_p, c_void_p)
libcrypto.ENGINE_load_private_key.restype = c_void_p
