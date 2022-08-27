# cython: language_level=3
from libc.stdint cimport uint8_t, uint32_t, int64_t
from libc.string cimport memcpy
cimport cython

from cpython.pycapsule cimport PyCapsule_New
from cpython.object cimport PyObject
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AS_STRING

from ftea.tea cimport tea_encrypt_qq,tea_encrypt, tea_encrypt_native_endian, tea_decrypt_qq,tea_decrypt,tea_decrypt_native_endian, encrypt_qq_len, swap_uint32, SHOULD_SWAP

@cython.freelist(8)
@cython.no_gc
@cython.final
cdef class TEA:
    cdef uint8_t _key[16]

    def __cinit__(self, const uint8_t[::1] key):
        self.key = key

    @property
    def key(self):
        cdef:
            bytes bt
            char* buffer
        if SHOULD_SWAP:  # small endian
            bt = PyBytes_FromStringAndSize(NULL, 16)
            if <PyObject*>bt == NULL:
                raise MemoryError
            buffer = PyBytes_AS_STRING(bt)
            (<uint32_t *>buffer)[0] = swap_uint32((<uint32_t *> self._key)[0])
            (<uint32_t *>buffer)[1] = swap_uint32((<uint32_t *> self._key)[1])
            (<uint32_t *>buffer)[2] = swap_uint32((<uint32_t *> self._key)[2])
            (<uint32_t *>buffer)[3] = swap_uint32((<uint32_t *> self._key)[3])
            return bt
        else:
            bt =  PyBytes_FromStringAndSize(<char*>self._key, 16)
            if <PyObject*>bt == NULL:
                raise MemoryError
            return bt

    @key.setter
    def key(self, const uint8_t[::1] key):
        assert key.shape[0] == 16, "key must be 16 bytes len"
        if SHOULD_SWAP:  # small endian
            (<uint32_t *> self._key)[0] = swap_uint32((<uint32_t *> &key[0])[0])
            (<uint32_t *> self._key)[1] = swap_uint32((<uint32_t *> &key[0])[1])
            (<uint32_t *> self._key)[2] = swap_uint32((<uint32_t *> &key[0])[2])
            (<uint32_t *> self._key)[3] = swap_uint32((<uint32_t *> &key[0])[3])
        else:
            memcpy(self._key, &key[0], 16)

    cpdef inline bytes encrypt_qq(self, const uint8_t[::1] text):
        cdef:
            int64_t src_len = <int64_t>text.shape[0]
            int64_t out_len = encrypt_qq_len(src_len)
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t>out_len)
            int64_t buffer_updated
            uint8_t* buffer_ptr
        if <PyObject*>buffer == NULL:
            raise MemoryError
        buffer_ptr = <uint8_t*>PyBytes_AS_STRING(buffer)
        with nogil:
            buffer_updated = tea_encrypt_qq(<uint32_t*>self._key, <const uint8_t *>&text[0],src_len, buffer_ptr, out_len)
        if buffer_updated< 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t encrypt_qq_into(self, const uint8_t[::1] text, uint8_t[::1] out) except -1:
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
            int64_t buffer_updated

        if out_len < encrypt_qq_len(src_len):
            raise ValueError("output buffer is too small")
        with nogil:
            buffer_updated = tea_encrypt_qq(<uint32_t *> self._key, <const uint8_t *> &text[0], src_len,
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
            int64_t buffer_updated
            uint8_t* buffer_ptr
        if <PyObject*>buffer == NULL:
            raise MemoryError
        buffer_ptr = <uint8_t*>PyBytes_AS_STRING(buffer)
        with nogil:
            buffer_updated = tea_encrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],<const uint8_t *> &text[0], src_len, buffer_ptr, out_len)
        if buffer_updated< 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t encrypt_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out) except -1:
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
            int64_t buffer_updated
        if out_len < encrypt_qq_len(src_len):
            raise ValueError("output buffer is too small")
        with nogil:
            buffer_updated = tea_encrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
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
            int64_t buffer_updated
            uint8_t *buffer_ptr
        if <PyObject*>buffer == NULL:
            raise MemoryError
        buffer_ptr = <uint8_t *> PyBytes_AS_STRING(buffer)
        with nogil:
            buffer_updated = tea_encrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                    <const uint8_t *> &text[0], src_len,
                                                    buffer_ptr, out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t encrypt_native_endian_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out) except -1:
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
            int64_t buffer_updated
        if out_len < encrypt_qq_len(src_len):
            raise ValueError("output buffer is too small")
        with nogil:
            buffer_updated = tea_encrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                    <const uint8_t *> &text[0], src_len,
                                                    <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

    cpdef inline bytes decrypt_qq(self, const uint8_t[::1] text):
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t> src_len)
            int64_t buffer_updated
            uint8_t *buffer_ptr
        if <PyObject*>buffer == NULL:
            raise MemoryError
        buffer_ptr = <uint8_t *> PyBytes_AS_STRING(buffer)
        with nogil:
            buffer_updated = tea_decrypt_qq(<uint32_t *> self._key, <const uint8_t *> &text[0], src_len,
                                                        buffer_ptr, src_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t decrypt_qq_into(self, const uint8_t[::1] text, uint8_t[::1] out) except -1:
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
            int64_t buffer_updated

        if out_len < src_len:
            raise ValueError("output buffer is too small")
        with nogil:
            buffer_updated = tea_decrypt_qq(<uint32_t *> self._key, <const uint8_t *> &text[0], src_len,
                                                        <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

    cpdef inline bytes decrypt(self, const uint8_t[::1] text, const uint8_t[::1] sumtable):
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            bytes buffer = PyBytes_FromStringAndSize(NULL, <Py_ssize_t> src_len)
            int64_t buffer_updated
            uint8_t* buffer_ptr
        if <PyObject*>buffer == NULL:
            raise MemoryError
        buffer_ptr = <uint8_t*>PyBytes_AS_STRING(buffer)
        with nogil:
            buffer_updated = tea_decrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],<const uint8_t *> &text[0], src_len, buffer_ptr, src_len)
        if buffer_updated< 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t decrypt_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out) except -1:
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
            int64_t buffer_updated
        if out_len < src_len:
            raise ValueError("output buffer is too small")
        with nogil:
            buffer_updated = tea_decrypt(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
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
            int64_t buffer_updated
            uint8_t *buffer_ptr 
        if <PyObject *> buffer == NULL:
            raise MemoryError
        buffer_ptr = <uint8_t *> PyBytes_AS_STRING(buffer)
        with nogil:
            buffer_updated = tea_decrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                    <const uint8_t *> &text[0], src_len,
                                                    buffer_ptr, src_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer[:buffer_updated]

    cpdef inline int64_t decrypt_native_endian_into(self, const uint8_t[::1] text, const uint8_t[::1] sumtable, uint8_t[::1] out) except -1:
        assert sumtable.shape[0] == 64, "sum table must be 64 bytes len"
        cdef:
            int64_t src_len = <int64_t> text.shape[0]
            int64_t out_len = <int64_t> out.shape[0]
            int64_t buffer_updated
        if out_len < src_len:
            raise ValueError("output buffer is too small")
        with nogil:
            buffer_updated = tea_decrypt_native_endian(<uint32_t *> self._key, <uint32_t *> &sumtable[0],
                                                    <const uint8_t *> &text[0], src_len,
                                                    <uint8_t *> &out[0], out_len)
        if buffer_updated < 0:
            raise ValueError("encrypt wrong")
        return buffer_updated

cpdef inline int64_t encrypt_len(int64_t src) nogil:
    return encrypt_qq_len(src)


ftea_encrypt_qq = PyCapsule_New(<void*>tea_encrypt_qq, "ftea.ftea_encrypt_qq", NULL)
ftea_decrypt_qq = PyCapsule_New(<void*>tea_decrypt_qq, "ftea.ftea_decrypt_qq", NULL)
ftea_encrypt = PyCapsule_New(<void*>tea_encrypt, "ftea.ftea_encrypt", NULL)
ftea_decrypt = PyCapsule_New(<void*>tea_decrypt, "ftea.ftea_decrypt", NULL)
ftea_encrypt_native_endian = PyCapsule_New(<void*>tea_encrypt_native_endian, "ftea.ftea_encrypt_native_endian", NULL)
ftea_decrypt_native_endian = PyCapsule_New(<void*>tea_decrypt_native_endian, "ftea.ftea_decrypt_native_endian", NULL)
ftea_encrypt_len = PyCapsule_New(<void*>encrypt_qq_len, "ftea.ftea_encrypt_len", NULL)
