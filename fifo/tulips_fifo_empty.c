#include <fifo/fifo.h>

tulips_fifo_error_t tulips_fifo_empty(tulips_fifo_t const fifo)
{
  if (fifo == TULIPS_FIFO_DEFAULT_VALUE) {
    return TULIPS_FIFO_IS_NULL;
  } else if (fifo->read_count == fifo->write_count) {
    return TULIPS_FIFO_OK;
  } else {
    return TULIPS_FIFO_NO;
  }
}
