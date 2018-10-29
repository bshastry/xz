///////////////////////////////////////////////////////////////////////////////
//
/// \file       fuzz.c
/// \brief      Fuzz test program for liblzma
//
//  Author:     Lasse Collin
//
//  This file has been put into the public domain.
//  You can do whatever you want with this file.
//
///////////////////////////////////////////////////////////////////////////////

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include "lzma.h"


// Chunk sizes (in bytes) to be used for passing input and output data.
//
// Passing the whole input file to liblzma at once and using an output
// buffer of 1-4 KiB would be the fastest, but using tiny odd-sized
// buffers exercises the corner cases where liblzma has to be able to
// stop and continue the decoding when running out of input data or
// the output buffer becomes full.
//
// One-byte chunks would be quite slow. As a compromise, bigger values are
// used to get better speed (only 50-150 % slower than the fast version).
#define IN_CHUNK_SIZE 13
#define OUT_CHUNK_SIZE 29


// Output buffer for decompressed data. This is write only; nothing
// cares about the actual data written here.
static uint8_t outbuf[OUT_CHUNK_SIZE];


extern int
LLVMFuzzerTestOneInput(const uint8_t *inbuf, size_t inbuf_size)
{
        // Some header values can make liblzma allocate a lot of RAM
        // (up to about 4 GiB with liblzma 5.2.x). We set a limit here to
        // prevent extreme allocations when fuzzing.
        const uint64_t memlimit = 300 << 20; // 300 MiB

        // Making strm static here and omitting the lzma_end() call at
        // the end of this function would cause subsequent calls to this
        // function to reuse the existing decoder state (lzma_stream_decoder()
        // would re-initialize it). It could be good to fuzz that that code
        // path too, but on the other hand it makes the current fuzzing round
        // depend on the previous rounds which isn't a good thing.
        /*static*/ lzma_stream strm = LZMA_STREAM_INIT;

        // Initialize a .xz decoder using the above memory usage limit.
        // Enable support for concatenated .xz files which is used when
        // decompressing regular .xz files (instead of data embedded inside
        // some other file format). Integrity checks on the uncompressed
        // data are ignored to make fuzzing more effective (incorrect check
        // values won't prevent the decoder from processing more input).
        //
        // The flag LZMA_IGNORE_CHECK doesn't disable verification of header
        // CRC32 values. Those checks are disabled when liblzma is built
        // with the #define FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION.
        lzma_ret ret = lzma_stream_decoder(&strm, memlimit,
                        LZMA_CONCATENATED | LZMA_IGNORE_CHECK);
        if (ret != LZMA_OK) {
                // This should never happen unless the system has
                // no free memory or address space to allow the small
                // allocations that the initialization requires.
                fprintf(stderr, "lzma_stream_decoder() failed (%d)\n", ret);
                abort();
        }

        strm.next_in = inbuf;
        strm.avail_in = 0;
        strm.next_out = outbuf;
        strm.avail_out = sizeof(outbuf);

        // Use LZMA_RUN until the last input byte is available to lzma_code().
        lzma_action action = LZMA_RUN;

        do {
                if (strm.avail_in == 0) {
                        // Add at most CHUNK_SIZE bytes of more input.
                        // We don't need to set strm.next_in as that
                        // already points to the correct byte.
                        if (inbuf_size > 0) {
                                strm.avail_in = inbuf_size < IN_CHUNK_SIZE
                                                ? inbuf_size
                                                : IN_CHUNK_SIZE;
                                inbuf_size -= strm.avail_in;
                        }

                        // Use LZMA_FINISH when the last input byte is
                        // available to lzma_code().
                        if (inbuf_size == 0)
                                action = LZMA_FINISH;
                }

                if (strm.avail_out == 0) {
                        // outbuf became full. We don't care about the
                        // uncompressed data there, so we simply reuse
                        // the outbuf and overwrite the old data.
                        strm.next_out = outbuf;
                        strm.avail_out = sizeof(outbuf);
                }

                ret = lzma_code(&strm, action);
        } while (ret == LZMA_OK);

        // LZMA_PROG_ERROR should never happen as long as the code calling
        // the liblzma functions is correct. Thus LZMA_PROG_ERROR is a sign
        // of a bug in either this function or in liblzma.
        if (ret == LZMA_PROG_ERROR) {
                fprintf(stderr, "lzma_code() returned LZMA_PROG_ERROR\n");
                abort();
        }

        // Free the allocated memory.
        //
        // NOTE: If strm were static, this should be commented out to allow
        // reusing the decoder memory on the next fuzzing round.
        lzma_end(&strm);

        return 0;
}