/*
 * Copyright 2016 Xavier R. Guérin
 */

#include <fifo/fifo.h>
#include <gtest/gtest.h>
#include <thread>

namespace
{

#define ITERATIONS 1000

static void reader_thread(tulips_fifo_t fifo)
{
  uint64_t data = 1;
  void *result = NULL;
  tulips_fifo_error_t error;
  for (size_t i = 0; i < ITERATIONS; i += 1) {
    do {
      error = tulips_fifo_front(fifo, &result);
    } while (error != TULIPS_FIFO_OK);
    ASSERT_EQ(data, *(uint64_t *)result);
    error = tulips_fifo_pop(fifo);
    ASSERT_EQ(TULIPS_FIFO_OK, error);
    data += 1;
  }
}

static void writer_thread(tulips_fifo_t fifo)
{
  uint64_t data = 1;
  tulips_fifo_error_t error;
  for (size_t i = 0; i < ITERATIONS; i += 1) {
    do {
      error = tulips_fifo_push(fifo, &data);
    } while (error != TULIPS_FIFO_OK);
    data += 1;
  }
}

} // namespace

TEST(FIFO, CreateAndDestroy)
{
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

TEST(FIFO, ReadWrite)
{
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
  void *result = NULL;
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
  const char *data = "hi to the world!";
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

TEST(FIFO, FullEmpty)
{
  tulips_fifo_t fifo = TULIPS_FIFO_DEFAULT_VALUE;
  tulips_fifo_error_t error;
  /**
   * Create success
   */
  error = tulips_fifo_create(16, 16, &fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /**
   * Push success
   */
  const char *data = "hi to the world!";
  for (int i = 0; i < 16; i += 1) {
    error = tulips_fifo_push(fifo, data);
    ASSERT_EQ(TULIPS_FIFO_OK, error);
  }
  /**
   * Push failure
   */
  error = tulips_fifo_push(fifo, data);
  ASSERT_EQ(TULIPS_FIFO_FULL, error);
  /**
   * Front and pop success
   */
  void *result;
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

TEST(FIFO, MultiThread)
{
  tulips_fifo_t fifo = TULIPS_FIFO_DEFAULT_VALUE;
  tulips_fifo_error_t error;
  /**
   * Create success
   */
  error = tulips_fifo_create(16, sizeof(uint64_t), &fifo);
  ASSERT_EQ(TULIPS_FIFO_OK, error);
  /*
   * Start the threads
   */
  std::thread t1(reader_thread, fifo);
  std::thread t0(writer_thread, fifo);
  /*
   * Join the threads
   */
  t0.join();
  t1.join();
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
