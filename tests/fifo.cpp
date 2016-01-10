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
   * State
   */
  error = tulips_fifo_empty(fifo);
  ASSERT_EQ(TULIPS_FIFO_YES, error);
  error = tulips_fifo_full(fifo);
  ASSERT_EQ(TULIPS_FIFO_NO, error);
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

TEST(FIFO, ReadWrite) {
  tulips_fifo_t fifo = TULIPS_FIFO_DEFAULT_VALUE;
  tulips_fifo_error_t error;
  /**
   * Create success
   */
  error = tulips_fifo_create(16, 16, &fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /**
   * Front failure
   */
  void * result = NULL;
  error = tulips_fifo_front(fifo, &result);
  ASSERT_EQ(TULIPS_FIFO_EMPTY, error);
  /**
   * Pop failure
   */
  error = tulips_fifo_pop(fifo);
  ASSERT_EQ(TULIPS_FIFO_EMPTY, error);
  /**
   * Push success
   */
  const char * data = "hi to the world!";
  error = tulips_fifo_push(fifo, data);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /*
   * Empty error
   */
  error = tulips_fifo_empty(fifo);
  ASSERT_EQ(TULIPS_FIFO_NO, error);
  /*
   * Full error
   */
  error = tulips_fifo_full(fifo);
  ASSERT_EQ(TULIPS_FIFO_NO, error);
  /**
   * Front success
   */
  error = tulips_fifo_front(fifo, &result);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  ASSERT_EQ(0, memcmp(result, data, 16));
  /**
   * Pop success
   */
  error = tulips_fifo_pop(fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /*
   * Empty success
   */
  error = tulips_fifo_empty(fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /**
   * Destroy success
   */
  error = tulips_fifo_destroy(&fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
}

TEST(FIFO, FullEmpty) {
  tulips_fifo_t fifo = TULIPS_FIFO_DEFAULT_VALUE;
  tulips_fifo_error_t error;
  /**
   * Create success
   */
  error = tulips_fifo_create(16, 16, &fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /**
   * Front failure
   */
  /**
   * Push success
   */
  const char * data = "hi to the world!";
  for (int i = 0; i < 16; i += 1) {
    error = tulips_fifo_push(fifo, data);
    ASSERT_EQ(TULIPS_FIFO_OK, error);
  }
  /**
   * Front and pop success
   */
  void * result;
  for (int i = 0; i < 16; i += 1) {
    error = tulips_fifo_front(fifo, &result);
    ASSERT_EQ(TULIPS_FIFO_OK, error);
    ASSERT_EQ(0, memcmp(result, data, 16));
    error = tulips_fifo_pop(fifo);
    ASSERT_EQ(TULIPS_FIFO_OK, error);
  }
  /**
   * Front and pop error
   */
  error = tulips_fifo_front(fifo, &result);
  ASSERT_EQ(TULIPS_FIFO_EMPTY, error);
  ASSERT_EQ(0, memcmp(result, data, 16));
  error = tulips_fifo_pop(fifo);
  ASSERT_EQ(TULIPS_FIFO_EMPTY, error);
  /*
   * Empty success
   */
  error = tulips_fifo_empty(fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /**
   * Destroy success
   */
  error = tulips_fifo_destroy(&fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
}
