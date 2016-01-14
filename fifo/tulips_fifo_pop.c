#include <fifo/fifo.h>
#include <string.h>

tulips_fifo_error_t tulips_fifo_pop(tulips_fifo_t const fifo)
{
	if (fifo == TULIPS_FIFO_DEFAULT_VALUE) {
		return TULIPS_FIFO_IS_NULL;
	} else if (tulips_fifo_empty(fifo) == TULIPS_FIFO_OK) {
		return TULIPS_FIFO_EMPTY;
	} else {
		fifo->read_count += 1;
		return TULIPS_FIFO_OK;
	}
}
