"""
Exception which extracts libcrypto error information
"""
from ctypes import c_ulong, c_char_p, create_string_buffer
from ctypescrypto import libcrypto, strings_loaded, pyver

__all__ = ['LibCryptoError', 'clear_err_stack']

if pyver == 2:
    def _get_error_str(err_code,buf):
        return libcrypto.ERR_error_string(err_code,buf)
else:
    def _get_error_str(err_code,buf):
        return libcrypto.ERR_error_string(err_code,buf).decode('utf-8')
class LibCryptoError(Exception):
    """
    Exception for libcrypto errors. Adds all the info, which can be
    extracted from internal (per-thread) libcrypto error stack to the message,
    passed to the constructor.
    """
    def __init__(self, msg):
        global strings_loaded
        if not strings_loaded:
            libcrypto.ERR_load_crypto_strings()
            strings_loaded = True
        err_code = libcrypto.ERR_get_error()
        mesg = msg
        buf = create_string_buffer(128)
        while err_code != 0:
            mesg += "\n\t" + _get_error_str(err_code, buf)
            err_code = libcrypto.ERR_get_error()
        super(LibCryptoError, self).__init__(mesg)

def clear_err_stack():
    """
    Clears internal libcrypto err stack. Call it if you've checked
    return code and processed exceptional situation, so subsequent
    raising of the LibCryptoError wouldn't list already handled errors
    """
    libcrypto.ERR_clear_error()

libcrypto.ERR_get_error.restype = c_ulong
libcrypto.ERR_error_string.restype = c_char_p
libcrypto.ERR_error_string.argtypes = (c_ulong, c_char_p)
