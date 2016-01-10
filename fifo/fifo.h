#ifndef TULIPS_FIFO_H_
#define TULIPS_FIFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <fifo/errors.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TULIPS_FIFO_DEFAULT_VALUE NULL

typedef struct __tulips_fifo {
  volatile uint64_t write_count;
  uint64_t          read_count;
  uint8_t           data[];
} * tulips_fifo_t;

tulips_fifo_error_t
tulips_fifo_create(const size_t depth, const size_t dlen,
                   tulips_fifo_t * const fifo);

tulips_fifo_error_t
tulips_fifo_destroy(tulips_fifo_t * const fifo);

#ifdef __cplusplus
}
#endif

#endif  // TULIPS_FIFO_H_
