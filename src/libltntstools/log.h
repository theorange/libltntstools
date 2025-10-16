
#pragma once

enum ltntstools_log_level
{
    LTNTSTOOLS_LL_NONE  = -1,
    LTNTSTOOLS_LL_ERROR =  0,
    LTNTSTOOLS_LL_WARN  =  1,
    LTNTSTOOLS_LL_INFO  =  2,
    LTNTSTOOLS_LL_DEBUG =  3,
    LTNTSTOOLS_LL_TRACE =  4,
};

typedef enum ltntstools_log_level ltntstools_log_level_t;

typedef int (*ltntstools_log_cb)(void *user_data,
                                   ltntstools_log_level_t level,
                                   const char* msg);

struct ltntstools_logger_s {
    void *user_data;
    ltntstools_log_cb cb;
    ltntstools_log_level_t threshold;
};

/**
 * Initialize a logger
 */
int ltntstools_logger_init(struct ltntstools_logger_s *ctx, ltntstools_log_cb cb, void *user_data, ltntstools_log_level_t threshold);

/**
 * Write a log entry. 
 * 
 * Use the LTN_* macros instead of this function to avoid the cost of parameter construction
 * for log entries that are below the logging threshold.
 */
int ltntstools_logger_checked_log(struct ltntstools_logger_s *ctx, ltntstools_log_level_t level, const char *msg, ...);

/**
 * Write a log entry (without threshold checking). 
 * 
 * Use the LTN_* macros instead of this function to avoid the cost of parameter construction
 * for log entries that are below the logging threshold.
 */
int ltntstools_logger_write(struct ltntstools_logger_s *ctx, ltntstools_log_level_t level, const char *msg, ...);

/**
 * Gets the log level.
 * @param ctx - the context, or NULL.
 */
ltntstools_log_level_t ltntstools_logger_get_threshold(struct ltntstools_logger_s *ctx);

/**
 * Gets a string representation of the log level.
 */
const char * ltntstools_logger_level_to_string(ltntstools_log_level_t level);


/**
 * The top-level logging macro.
 * 
 * This is wrapped in a do-while to avoid some expansion gotchas.
 * It performs the threshold
 */
#define LTN_LOG(ctx, level, ...)                                     \
    do {                                                             \
        if (level <= ltntstools_logger_get_threshold(ctx)) {         \
            ltntstools_logger_write(ctx, level, __VA_ARGS__);        \
        }                                                            \
    } while (0)


/* General Use Macros. These are what you should generally use for logging */

#define LTN_ERROR(ctx, ...) LTN_LOG(ctx, LTNTSTOOLS_LL_ERROR, __VA_ARGS__)
#define LTN_WARN(ctx, ...)  LTN_LOG(ctx, LTNTSTOOLS_LL_WARN, __VA_ARGS__)
#define LTN_INFO(ctx, ...)  LTN_LOG(ctx, LTNTSTOOLS_LL_INFO, __VA_ARGS__)
#define LTN_DEBUG(ctx, ...) LTN_LOG(ctx, LTNTSTOOLS_LL_DEBUG, __VA_ARGS__)
#define LTN_TRACE(ctx, ...) LTN_LOG(ctx, LTNTSTOOLS_LL_TRACE, __VA_ARGS__)