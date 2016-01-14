#include <fifo/fifo.h>

tulips_fifo_error_t tulips_fifo_full(tulips_fifo_t const fifo)
{
	if (fifo == TULIPS_FIFO_DEFAULT_VALUE) {
		return TULIPS_FIFO_IS_NULL;
	} else if (fifo->write_count - fifo->read_count == fifo->depth) {
		return TULIPS_FIFO_OK;
	} else {
		return TULIPS_FIFO_NO;
	}
}
