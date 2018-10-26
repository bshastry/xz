#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <lzma.h>

static bool
init_decoder(lzma_stream *strm)
{
    /* Initialize lzma stream decoder, setting a memory limit of 500 MB,
     *  and setting the LZMA_IGNORE_CHECK flag which instructs the
     *  decoder to disable CRC checks on compressed data.
     */
    lzma_ret ret = lzma_stream_decoder(
            strm, /* memory limit */ 500 << 20,
            LZMA_CONCATENATED | LZMA_IGNORE_CHECK);

    if (ret == LZMA_OK)
        return true;

    /* The flag "FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION" is defined
     * by the fuzzer build script. We use it here to disable debug
     * messages. Disabling debug messages in fuzzer test harnesses seems
     *  to be the norm for oss-fuzz targets.
     */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Something went wrong, print an informative debug message
    const char *msg;
    switch (ret) {
    case LZMA_MEM_ERROR:
        msg = "Memory allocation failed";
        break;

    case LZMA_OPTIONS_ERROR:
        msg = "Unsupported decompressor flags";
        break;

    default:
        msg = "Unknown error, possibly a bug";
        break;
    }

    fprintf(stderr, "Error initializing the decoder: %s (error code %u)\n",
            msg, ret);
#endif
    return false;
}

static bool
decompress(lzma_stream *strm, const uint8_t *inbuf, size_t inlen,
           uint8_t *outbuf, size_t outlen)
{
    size_t remainlen = inlen;

    lzma_action action = LZMA_RUN;

    strm->next_in = NULL;
    strm->avail_in = 0;
    strm->next_out = outbuf;
    strm->avail_out = outlen;

    // Decode BUFSIZ==8192 bytes of inbuf at a time
    while (true) {

        // TODO: We invoke lzma_code twice when remainlen == 0.
        // Is this okay?

        if (strm->avail_in == 0 && remainlen != 0) {
            strm->next_in = inbuf;
            strm->avail_in = (remainlen > BUFSIZ) ? BUFSIZ : remainlen;
            remainlen -= strm->avail_in;

            if (remainlen == 0)
                action = LZMA_FINISH;
        }

        lzma_ret ret = lzma_code(strm, action);
        /* LZMA_PROG_ERROR should be rarely, if ever, happen
         * The assertion codifies this expectation.
         */
        assert(ret != LZMA_PROG_ERROR);

        // TODO: Is this code trying to overwrite outbuf when outlen
        // is exhausted? If so, is that okay?
        if (strm->avail_out == 0 || ret == LZMA_STREAM_END) {
            strm->next_out = outbuf;
            strm->avail_out = outlen;
        }

        if (ret != LZMA_OK) {
            if (ret == LZMA_STREAM_END)
                return true;

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            const char *msg;
            switch (ret) {
            case LZMA_MEM_ERROR:
                msg = "Memory allocation failed";
                break;

            case LZMA_FORMAT_ERROR:
                // .xz magic bytes weren't found.
                msg = "The input is not in the .xz format";
                break;

            case LZMA_OPTIONS_ERROR:
                msg = "Unsupported compression options";
                break;

            case LZMA_DATA_ERROR:
                msg = "Compressed file is corrupt";
                break;

            case LZMA_BUF_ERROR:
                msg = "Compressed file is truncated or "
                        "otherwise corrupt";
                break;

            default:
                msg = "Unknown error, possibly a bug";
                break;
            }

            fprintf(stderr, "Decoder error: "
                    "%s (error code %u)\n",
                    msg, ret);
#endif
            return false;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

    lzma_stream strm = LZMA_STREAM_INIT;

    // Null data is uninteresting
    if (size == 0) {
        return 0;
    }

    // Init decoder.
    if (!init_decoder(&strm)) {
        // Decoder initialization failed. There's no point
        // retrying, so bail out.
        return 0;
    }

    uint8_t outbuf[BUFSIZ];

    if (!decompress(&strm, data, size, outbuf, BUFSIZ)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        fprintf(stderr, "Decode failure\n");
#endif
    }

    // Free the memory allocated for the decoder.
    lzma_end(&strm);
    return 0;
}
