#ifndef TULIPS_FIFO_H_
#define TULIPS_FIFO_H_

#ifdef __cplusplus
extern "C" {
#define restrict __restrict
#endif

#include <fifo/errors.h>
#include <stddef.h>
#include <stdint.h>

#define TULIPS_FIFO_DEFAULT_VALUE NULL

typedef struct __tulips_fifo {
  size_t depth;
  size_t data_len;
  volatile uint64_t write_count;
  uint64_t read_count;
  uint8_t data[];
} * restrict tulips_fifo_t;

tulips_fifo_error_t tulips_fifo_create(const size_t depth, const size_t dlen,
                                       tulips_fifo_t *const fifo);

tulips_fifo_error_t tulips_fifo_destroy(tulips_fifo_t *const fifo);

tulips_fifo_error_t tulips_fifo_empty(tulips_fifo_t const fifo);

tulips_fifo_error_t tulips_fifo_full(tulips_fifo_t const fifo);

tulips_fifo_error_t tulips_fifo_push(tulips_fifo_t const fifo,
                                     const void *restrict const data);

tulips_fifo_error_t tulips_fifo_front(tulips_fifo_t const fifo,
                                      void **const data);

tulips_fifo_error_t tulips_fifo_pop(tulips_fifo_t const fifo);

#ifdef __cplusplus
}
#endif

#endif // TULIPS_FIFO_H_

/* vim: set ft=c */
