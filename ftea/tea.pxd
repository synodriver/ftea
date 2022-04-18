# cython: language_level=3
from libc.stdint cimport uint8_t, uint32_t, int64_t

cdef extern from "simplecrypto.h" nogil:
    int64_t tea_encrypt_qq(const uint32_t t[4], const uint8_t *src, int64_t src_len, uint8_t *out, int64_t out_len)
    int64_t tea_encrypt(const uint32_t t[4], const uint32_t sumtable[0x10], const uint8_t *src, int64_t src_len,
                        uint8_t *out, int64_t out_len)
    int64_t tea_encrypt_native_endian(const uint32_t t[4], const uint32_t sumtable[0x10], const uint8_t *src,
                                      int64_t src_len, uint8_t *out, int64_t out_len)
    int64_t tea_decrypt_qq(const uint32_t t[4], const uint8_t *src, int64_t src_len, uint8_t *out, int64_t out_len)
    int64_t tea_decrypt(const uint32_t t[4], const uint32_t sumtable[0x10], const uint8_t *src, int64_t src_len,
                        uint8_t *out, int64_t out_len)
    int64_t tea_decrypt_native_endian(const uint32_t t[4], const uint32_t sumtable[0x10], const uint8_t *src,
                                      int64_t src_len, uint8_t *out, int64_t out_len)

cdef extern from * nogil:
    """
int64_t encrypt_qq_len(int64_t src_len)
{
    int64_t fill = 10 - (src_len + 1) % 8;
    return fill + src_len + 7;
}
    """
    int64_t encrypt_qq_len(int64_t src_len)