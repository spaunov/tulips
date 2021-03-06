#ifndef TULIPS_ERRORS_H_
#define TULIPS_ERRORS_H_

#ifdef __cplusplus
extern "C" {
#endif

  typedef enum __tulips_fifo_error {
    TULIPS_FIFO_NO                = 0xFF,
    TULIPS_FIFO_YES               = 0x00,
    TULIPS_FIFO_OK                = 0x00,
    TULIPS_FIFO_IS_NULL           = 0x01,
    TULIPS_FIFO_ALREADY_ALLOCATED = 0x02,
    TULIPS_FIFO_INVALID_DEPTH     = 0x03,
    TULIPS_FIFO_INVALID_DATA_LEN  = 0x04,
    TULIPS_FIFO_MALLOC_FAILED     = 0x05,
    TULIPS_FIFO_EMPTY             = 0x06,
    TULIPS_FIFO_FULL              = 0x07
  } tulips_fifo_error_t;

#ifdef __cplusplus
}
#endif

#endif  // TULIPS_ERRORS_H_
