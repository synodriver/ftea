# cython: language_level=3
cimport cython
from cpython.mem cimport PyMem_Free, PyMem_Malloc
from libc.stdint cimport uint8_t
from libc.string cimport memset

from ftea.xtea cimport (xtea_declen, xtea_decode, xtea_decodecbc,
                        xtea_decodeecb, xtea_enclen, xtea_encode,
                        xtea_encodecbc, xtea_encodeecb, xtea_setkey, xtea_t)


cpdef inline int enclen(int l):
    return xtea_enclen(l)

cpdef inline int declen(int l):
    return xtea_declen(l)

@cython.freelist(8)
@cython.no_gc
@cython.final
cdef class XTEA:
    cdef xtea_t _tea
    def __cinit__(self, const uint8_t[::1] key):
        assert key.shape[0] == 16
        xtea_setkey(&self._tea, <const unsigned char*>&key[0])

    cpdef inline int encode_into(self, const uint8_t[::1] data, uint8_t[::1] outbuf, uint8_t[::1] iv):
        cdef int ret
        with nogil:
            ret = xtea_encode(&self._tea, <void*>&outbuf[0], <const void *>&data[0], <int>data.shape[0], &iv[0])
        return ret

    cpdef inline int decode_into(self, const uint8_t[::1] data, uint8_t[::1] outbuf, uint8_t[::1] iv):
        cdef int ret
        with nogil:
            ret = xtea_decode(&self._tea, <void*>&outbuf[0], <const void *>&data[0], <int>data.shape[0], &iv[0])
        return ret