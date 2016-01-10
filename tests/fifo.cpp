/*
 * Copyright 2016 Xavier R. Guérin
 */

#include <fifo/fifo.h>
#include <gtest/gtest.h>

TEST(FIFO, CreateAndDestroy) {
  tulips_fifo_t fifo = TULIPS_FIFO_DEFAULT_VALUE;
  tulips_fifo_error_t error;
  /**
   * Invalid depth
   */
  error = tulips_fifo_create(0, 0, &fifo);
  ASSERT_EQ(TULIPS_FIFO_INVALID_DEPTH, error);
  /**
   * Invalid data length
   */
  error = tulips_fifo_create(16, 0, &fifo);
  ASSERT_EQ(TULIPS_FIFO_INVALID_DATA_LEN, error);
  /**
   * Create success
   */
  error = tulips_fifo_create(16, 16, &fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /**
   * Already allocated
   */
  error = tulips_fifo_create(16, 16, &fifo);
  ASSERT_EQ(TULIPS_FIFO_ALREADY_ALLOCATED, error);
  /**
   * Destroy success
   */
  error = tulips_fifo_destroy(&fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /**
   * Already deallocated
   */
  error = tulips_fifo_destroy(&fifo);
  ASSERT_EQ(TULIPS_FIFO_IS_NULL, error);
}
