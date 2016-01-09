#ifndef TULIPS_FIFO_H_
#define TULIPS_FIFO_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct __tulips_fifo {
  volatile uint64_t write_count;
  uint64_t          read_count;
  uint8_t           data[];
} * tulips_fifo_t;

tulips_fifo_t tulips_fifo_create();
void tulips_fifo_destroy(tulips_fifo_t fifo);

#endif  // TULIPS_FIFO_H_
