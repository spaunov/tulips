#include <fifo/fifo.h>
#include <string.h>

tulips_fifo_error_t tulips_fifo_front(tulips_fifo_t const fifo,
                                      void **const data)
{
  if (fifo == TULIPS_FIFO_DEFAULT_VALUE) {
    return TULIPS_FIFO_IS_NULL;
  } else if (tulips_fifo_empty(fifo) == TULIPS_FIFO_OK) {
    return TULIPS_FIFO_EMPTY;
  } else {
    size_t index = fifo->read_count % fifo->depth;
    *data = fifo->data + index * fifo->data_len;
    return TULIPS_FIFO_OK;
  }
}
