#include <fifo/fifo.h>
#include <string.h>

tulips_fifo_error_t tulips_fifo_push(tulips_fifo_t const fifo,
                                     const void *restrict const data)
{
  if (fifo == TULIPS_FIFO_DEFAULT_VALUE) {
    return TULIPS_FIFO_IS_NULL;
  } else if (tulips_fifo_full(fifo) == TULIPS_FIFO_OK) {
    return TULIPS_FIFO_FULL;
  } else {
    size_t index = fifo->write_count % fifo->depth;
    void *result = fifo->data + index * fifo->data_len;
    memcpy(result, data, fifo->data_len);
    fifo->write_count += 1;
    return TULIPS_FIFO_OK;
  }
}
