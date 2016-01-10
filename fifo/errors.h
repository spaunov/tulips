#ifndef TULIPS_ERRORS_H_
#define TULIPS_ERRORS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum __tulips_fifo_error {
  TULIPS_FIFO_OK                = 0,
  TULIPS_FIFO_IS_NULL           = 1,
  TULIPS_FIFO_ALREADY_ALLOCATED = 2,
  TULIPS_FIFO_INVALID_DEPTH     = 3,
  TULIPS_FIFO_INVALID_DATA_LEN  = 4,
  TULIPS_FIFO_MALLOC_FAILED     = 5,
} tulips_fifo_error_t;

#ifdef __cplusplus
}
#endif

#endif  // TULIPS_ERRORS_H_
