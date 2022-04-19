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
uint8_t is_le()
{
    int16_t data = 0x1234;
    int8_t *p = (int8_t *)&data;
    if (p[0]<p[1])
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

#ifdef _WIN32
    #define swap_uint32 _byteswap_ulong
#else
    #define swap_uint32 __builtin_bswap32
#endif /* _WIN32 */
    """
    int64_t encrypt_qq_len(int64_t src_len)
    uint8_t is_le()
    uint32_t swap_uint32(uint32_t data)