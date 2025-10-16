#pragma once
#include "log.h"

/* SMPTE 2022-7 Receiver implementation -------------------------------------------------------------- */

typedef struct smpte_2022_7_rx_s smpte_2022_7_rx_t;
typedef int (*smpte_2022_7_rx_cb)(void *user_data, unsigned char *data, int len);

smpte_2022_7_rx_t * smpte_2022_7_rx_new(smpte_2022_7_rx_cb cb, void *user_data);
int smpte_2022_7_rx_free(smpte_2022_7_rx_t *handle);

/**
 * @param data - a single RTP packet.
 */
int smpte_2022_7_rx_push_packet(smpte_2022_7_rx_t *handle, int which, unsigned char *data, int len);

/**
 * @param data - a byte array of RTP packets. There should be an integer number of packets available.
 */
int smpte_2022_7_rx_push_packets(smpte_2022_7_rx_t *handle, int which, unsigned char *data, int len);

/**
 * Specify the logger (optional). None will be provided by default.
 * A copy will be made of the logger contents, so the logger instance can be stack-allocated.
 */
int smpte_2022_7_rx_set_logger(smpte_2022_7_rx_t *ctx, const struct ltntstools_logger_s *logger);


/* SMPTE 2022-7 Transmitter implementation -------------------------------------------------------------- */

typedef struct smpte_2022_7_tx_s smpte_2022_7_tx_t;
typedef int (*smpte_2022_7_tx_cb)(void *user_data, int which, unsigned char *data, int len);

smpte_2022_7_tx_t * smpte_2022_7_tx_new(smpte_2022_7_tx_cb cb, void *user_data, int legs);
int smpte_2022_7_tx_free(smpte_2022_7_tx_t *handle);

/**
 * @param ctx  - the context.
 * @param data - a byte array of UDP TS packets. This should should not be RTP packets.
 * @param len  - the data length.
 * @parma ts   - A pointer to the RTP timestamp. One will be created if this value is null.
 */
int smpte_2022_7_tx_push_packets(smpte_2022_7_tx_t *ctx, unsigned char *data, int len, uint32_t *ts);

/**
 * Specify the logger (optional). None will be provided by default.
 * A copy will be made of the logger contents, so the logger instance can be stack-allocated.
 */
int smpte_2022_7_tx_set_logger(smpte_2022_7_tx_t *ctx, const struct ltntstools_logger_s *logger);