# cython: language_level=3

cdef extern from "xtea.h" nogil:
    ctypedef struct xtea_t:
        unsigned int key[4]

    void xtea_setkey(xtea_t *xtea, const unsigned char key[16])

    void xtea_encodeecb(xtea_t *xtea, unsigned char outbuf[8],
                        const unsigned char inbuf[8])
    void xtea_decodeecb(xtea_t *xtea, unsigned char outbuf[8],
                        const unsigned char inbuf[8])

    # the length of inbuf/outbuf, multiple of 8
    int xtea_encodecbc(xtea_t *xtea, unsigned char *outbuf,
                       const unsigned char *inbuf, int len,
                       unsigned char iv[8])
    int xtea_decodecbc(xtea_t *xtea, unsigned char *outbuf,
                       const unsigned char *inbuf, int len,
                       unsigned char iv[8])

    int xtea_enclen(int len)
    int xtea_declen(int len)

    int xtea_encode(xtea_t *xtea, void *outbuf, const void *inbuf,
                    int inlen, unsigned char iv[8])
    int xtea_decode(xtea_t *xtea, void *outbuf, const void *inbuf,
                    int inlen, unsigned char iv[8])
