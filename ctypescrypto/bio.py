"""
Interface to OpenSSL BIO library
"""
from ctypescrypto import libcrypto,pyver, inttype, chartype
from ctypes import c_char_p, c_void_p, c_int, string_at, c_long
from ctypes import POINTER, byref, create_string_buffer
class Membio(object):
    """
    Provides interface to OpenSSL memory bios
    use str() or unicode() to get contents of writable bio
    use bio member to pass to libcrypto function
    
    """
    def __init__(self, data=None, clone=False):
        """
        If data is specified, creates read-only BIO. 
        If clone is True, makes copy of data in the instance member
        If data is
        None, creates writable BIO, contents of which can be retrieved
        by str() or unicode()
        
        """
        if data is None:
            method = libcrypto.BIO_s_mem()
            self.bio = libcrypto.BIO_new(method)
        else:
            if isinstance(data, chartype):
                data = data.encode("utf-8")
                clone = True
            if clone :
                self.data = data
                self.bio = libcrypto.BIO_new_mem_buf(c_char_p(self.data), len(data))
            else:
                self.bio = libcrypto.BIO_new_mem_buf(c_char_p(data), len(data))
                
    def __del__(self):
        """
        Cleans up memory used by bio
        """
        if hasattr(self,'bio'):
            libcrypto.BIO_free(self.bio)
            del self.bio

    def __bytes__(self):
        """
        Returns current contents of buffer as byte string
        """
        string_ptr = c_char_p(None)
        string_len = libcrypto.BIO_ctrl(self.bio, 3, 0, byref(string_ptr))
        return string_at(string_ptr, string_len)

    def __unicode__(self):
        """
        Attempts to interpret current contents of buffer as UTF-8 string
        and convert it to unicode
        """
        return self.__bytes__().decode("utf-8")
    if pyver == 2:
        __str__ = __bytes__
    else: 
        __str__ = __unicode__
    def read(self, length=None):
        """
        Reads data from readble BIO. For test purposes.
        @param length - if specifed, limits amount of data read.
        If not BIO is read until end of buffer
        """
        if not length is None:
            if not isinstance(length, inttype) :
                raise TypeError("length to read should be number")
            buf = create_string_buffer(length)
            readbytes = libcrypto.BIO_read(self.bio, buf, length)
            if readbytes == -2:
                raise NotImplementedError("Function is not supported by" +
                                          "this BIO")
            if readbytes == -1:
                raise IOError
            if readbytes == 0:
                return b""
            return buf.raw[:readbytes]
        else:
            buf = create_string_buffer(1024)
            out = b""
            readbytes = 1
            while readbytes > 0:
                readbytes = libcrypto.BIO_read(self.bio, buf, 1024)
                if readbytes == -2:
                    raise NotImplementedError("Function is not supported by " +
                                              "this BIO")
                if readbytes == -1:
                    raise IOError
                if readbytes > 0:
                    out += buf.raw[:readbytes]
            return out

    def write(self, data):
        """
        Writes data to writable bio. For test purposes
        """
        if pyver == 2:
             if isinstance(data, unicode):
                data = data.encode("utf-8")
             else:
                data = str(data)
        else:
             if not isinstance(data, bytes): 
                data=str(data).encode("utf-8")   

        written = libcrypto.BIO_write(self.bio, data, len(data))
        if written == -2:
            raise NotImplementedError("Function not supported by this BIO")
        if written < len(data):
            raise IOError("Not all data were successfully written")

    def reset(self):
        """
        Resets the read-only bio to start and discards all data from
        writable bio
        """
        libcrypto.BIO_ctrl(self.bio, 1, 0, None)

__all__ = ['Membio']
libcrypto.BIO_s_mem.restype = c_void_p
libcrypto.BIO_new.restype = c_void_p
libcrypto.BIO_new.argtypes = (c_void_p, )
libcrypto.BIO_ctrl.restype = c_long
libcrypto.BIO_ctrl.argtypes = (c_void_p, c_int, c_long, POINTER(c_char_p))
libcrypto.BIO_read.argtypes = (c_void_p, c_char_p, c_int)
libcrypto.BIO_write.argtypes = (c_void_p, c_char_p, c_int)
libcrypto.BIO_free.argtypes = (c_void_p, )
libcrypto.BIO_new_mem_buf.restype = c_void_p
libcrypto.BIO_new_mem_buf.argtypes = (c_char_p, c_int)
