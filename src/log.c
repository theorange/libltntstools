#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "libltntstools/log.h"

static int default_logger(void *user_data, ltntstools_log_level_t level, const char *msg) {    
   struct timespec tm;
   clock_gettime(CLOCK_REALTIME, &tm);

   char tbuf[26];   
   struct tm tmp;
   strftime(tbuf, sizeof(tbuf), "%FT%T", gmtime_r(&tm.tv_sec, &tmp));

   return fprintf(user_data, "%s.%06dZ - %5s: %s\n", tbuf, (int)(tm.tv_nsec / 1000), ltntstools_logger_level_to_string(level), msg);
}

int ltntstools_logger_init(struct ltntstools_logger_s *ctx, ltntstools_log_cb cb, void *user_data, ltntstools_log_level_t threshold) {
    ctx->cb = default_logger;
    ctx->user_data = user_data;
    ctx->threshold = threshold > LTNTSTOOLS_LL_TRACE ? LTNTSTOOLS_LL_TRACE : threshold;
    if (cb) {    
        ctx->cb = cb;
    }
    if (!user_data) {
        ctx->user_data = stderr;
    }
    return 0;
}

int ltntstools_logger_checked_log(struct ltntstools_logger_s *ctx, ltntstools_log_level_t level, const char *fmt, ...) {
    if (!ctx || !ctx->cb) return 0;
#if _GNU_SOURCE    
    if (level < ctx->threshold) return -ENOMSG;
    char *ptr = NULL;
    va_list arg_list;
    va_start(arg_list, fmt);
    int rc = vasprintf(&ptr, fmt, arg_list);
    va_end(arg_list);
    ctx->cb(ctx->user_data, level, ptr);
    free(ptr);
    return rc;
#endif    
}

int ltntstools_logger_write(struct ltntstools_logger_s *ctx, ltntstools_log_level_t level, const char *fmt, ...) {
    if (!ctx || !ctx->cb) return 0;
#if _GNU_SOURCE
    char *ptr = NULL;
    va_list arg_list;
    va_start(arg_list, fmt);
    int rc = vasprintf(&ptr, fmt, arg_list);
    va_end(arg_list);
    ctx->cb(ctx->user_data, level, ptr);
    free(ptr);
    return rc;
#endif    
}

ltntstools_log_level_t ltntstools_logger_get_threshold(struct ltntstools_logger_s *ctx) {
    if (!ctx || !ctx->cb) return LTNTSTOOLS_LL_NONE;
    return ctx->threshold;
}

const char *ltntstools_logger_level_to_string(int level) {
    #define _L2S(x) case x: return #x + 14;
    switch (level) {
        _L2S(LTNTSTOOLS_LL_NONE)
        _L2S(LTNTSTOOLS_LL_ERROR)
        _L2S(LTNTSTOOLS_LL_WARN)
        _L2S(LTNTSTOOLS_LL_INFO)
        _L2S(LTNTSTOOLS_LL_DEBUG)
        _L2S(LTNTSTOOLS_LL_TRACE)
        default:
            return (level > LTNTSTOOLS_LL_TRACE) ? "TRACE" : "UNKNOWN";
    }
    #undef _L2S
}