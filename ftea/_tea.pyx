# cython: language_level=3
from libc.stdint cimport uint8_t, uint32_t, int64_t
from libc.string cimport memcpy
cimport cython

from cpython.object cimport PyObject
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AsString

from ftea.tea cimport tea_encrypt_qq,tea_encrypt, tea_encrypt_native_endian, tea_decrypt_qq,tea_decrypt,tea_decrypt_native_endian, encrypt_qq_len

@cython.final
cdef class TEA:
    cdef uint8_t _key[16]

    def __cinit__(self, const uint8_t[::1] key):
        self.key = key

    @property
    def key(self):
        return PyBytes_FromStringAndSize(<char*>self._key, 16)

    @key.setter
    def key(self, const uint8_t[::1] key):
        assert key.shape[0] == 16, "key must be 16 bytes len"
        memcpy(self._key, &key[0], 16)

    cpdef inline bytes encrypt_qq(self, const uint8_t[::1] text):
        cdef:
            int64_t src_len = <int64_t>text.shape[0]
            int64_t out_len = encrypt_qq_len(src_len)
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t>out_len)
        if <PyObject*>buffer == NULL:
            raise MemoryError

        cdef int64_t buffer_updated = tea_encrypt_qq(<uint32_t*>self._key, <const uint8_t *>&text[0],src_len, <uint8_t*>PyBytes_AsString(buffer), out_len)
        if buffer_updated< 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t encrypt_qq_into(self, const uint8_t[::1] text, uint8_t[::1] out):
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]

        if out_len < encrypt_qq_len(src_len):
            raise ValueError("output buffer is too small")
        cdef int64_t buffer_updated = tea_encrypt_qq(<uint32_t *> self._key, <const uint8_t *> &text[0], src_len,
                                                     <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

    cpdef inline bytes encrypt(self, const uint8_t[::1] text, const uint8_t[::1] sumtable):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = encrypt_qq_len(src_len)
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t> out_len)
        if <PyObject*>buffer == NULL:
            raise MemoryError

        cdef int64_t buffer_updated = tea_encrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],<const uint8_t *> &text[0], src_len,<uint8_t*>PyBytes_AsString(buffer), out_len )
        if buffer_updated< 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t encrypt_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
        if out_len < encrypt_qq_len(src_len):
            raise ValueError("output buffer is too small")
        cdef int64_t buffer_updated = tea_encrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                  <const uint8_t *> &text[0], src_len,
                                                  <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

    cpdef inline bytes encrypt_native_endian(self, const uint8_t[::1] text, const uint8_t[::1] sumtable):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = encrypt_qq_len(src_len)
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t> out_len)
        if <PyObject*>buffer == NULL:
            raise MemoryError

        cdef int64_t buffer_updated = tea_encrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                  <const uint8_t *> &text[0], src_len,
                                                  <uint8_t *> PyBytes_AsString(buffer), out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t encrypt_native_endian_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
        if out_len < encrypt_qq_len(src_len):
            raise ValueError("output buffer is too small")
        cdef int64_t buffer_updated = tea_encrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                  <const uint8_t *> &text[0], src_len,
                                                  <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

    cpdef inline bytes decrypt_qq(self, const uint8_t[::1] text):
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t> src_len)
        if <PyObject*>buffer == NULL:
            raise MemoryError

        cdef int64_t buffer_updated = tea_decrypt_qq(<uint32_t *> self._key, <const uint8_t *> &text[0], src_len,
                                                     <uint8_t *> PyBytes_AsString(buffer), src_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t decrypt_qq_into(self, const uint8_t[::1] text, uint8_t[::1] out):
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]

        if out_len < src_len:
            raise ValueError("output buffer is too small")
        cdef int64_t buffer_updated = tea_decrypt_qq(<uint32_t *> self._key, <const uint8_t *> &text[0], src_len,
                                                     <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

    cpdef inline bytes decrypt(self, const uint8_t[::1] text, const uint8_t[::1] sumtable):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t> src_len)
        if <PyObject*>buffer == NULL:
            raise MemoryError

        cdef int64_t buffer_updated = tea_decrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],<const uint8_t *> &text[0], src_len,<uint8_t*>PyBytes_AsString(buffer), src_len)
        if buffer_updated< 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t decrypt_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
        if out_len < src_len:
            raise ValueError("output buffer is too small")
        cdef int64_t buffer_updated = tea_decrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                  <const uint8_t *> &text[0], src_len,
                                                  <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

    cpdef inline bytes decrypt_native_endian(self, const uint8_t[::1] text, const uint8_t[::1] sumtable):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t> src_len)
        if <PyObject *> buffer == NULL:
            raise MemoryError

        cdef int64_t buffer_updated = tea_decrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                  <const uint8_t *> &text[0], src_len,
                                                  <uint8_t *> PyBytes_AsString(buffer), src_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t decrypt_native_endian_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
        if out_len < src_len:
            raise ValueError("output buffer is too small")
        cdef int64_t buffer_updated = tea_decrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                  <const uint8_t *> &text[0], src_len,
                                                  <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

cpdef inline int64_t encrypt_len(int64_t src):
    return encrypt_qq_len(src)
