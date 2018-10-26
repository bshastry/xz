#include "lzma.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t buf[BUFSIZ];

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  lzma_stream strm = LZMA_STREAM_INIT;
  lzma_ret ret = lzma_stream_decoder(&strm, /* memory limit */ 500 << 20,
    LZMA_CONCATENATED | LZMA_IGNORE_CHECK);
  if (ret != LZMA_OK)
    return 0;

  memset((void *)&buf, 0, BUFSIZ);

  strm.avail_out = 0;
  strm.next_in = data;
  strm.avail_in = size;
  lzma_action action = LZMA_RUN;

  while (1) {
    if (!strm.avail_in)
      action = LZMA_FINISH;
    if (!strm.avail_out) {
      strm.next_out = buf;
      strm.avail_out = BUFSIZ;
    }
    ret = lzma_code(&strm, action);
    if (ret == LZMA_PROG_ERROR) {
        abort();
    }
    else if (ret != LZMA_OK) {
        break;
    }
  }
  lzma_end(&strm);
  return 0;
}