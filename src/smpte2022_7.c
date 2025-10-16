#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <arpa/inet.h>

#include "libltntstools/smpte2022_7.h"

#define TS_PACKET_SIZE      188
#define TS_PER_RTP_PACKET   7
#define RTP_PAYLOAD_SIZE    (TS_PACKET_SIZE * TS_PER_RTP_PACKET)
#define RTP_HEADER_SIZE     12
#define RTP_MAX_PACKET_SIZE (RTP_HEADER_SIZE + RTP_PAYLOAD_SIZE)
#define MAX_LEGS            3



struct pkt_entry {
    uint16_t seq;
    uint32_t ts;
    int len;
    unsigned char *data;
    struct timespec tm;
};

struct smpte_2022_7_rx_s {
    smpte_2022_7_rx_cb cb;
    void *user_data;
    struct pkt_entry buf[1024];  // simple fixed buffer
    int buf_count;
    uint16_t expected_seq;
    uint32_t last_ts;
    bool initialized;
    int verbose;
    struct ltntstools_logger_s logger;
};

typedef struct {
    
    uint16_t seq;
    uint32_t timestamp;
    uint32_t ssrc;
} leg_state_t;

struct smpte_2022_7_tx_s {
    smpte_2022_7_tx_cb cb;
    void *user_data;
    int num_legs;    
    uint16_t seq;
    unsigned char buffer[RTP_MAX_PACKET_SIZE];
    int payload_len;
    struct ltntstools_logger_s logger;
};

// <bitstream_functions> ---------------------------------------------------------

static inline bool rtp_check_hdr(const uint8_t *p_rtp)
{
    return (p_rtp[0] & 0xc0) == 0x80;
}

static inline uint8_t rtp_get_type(const uint8_t *p_rtp)
{
    return p_rtp[1] & 0x7f;
}

static inline uint16_t rtp_get_seqnum(const uint8_t *p_rtp)
{
    return (p_rtp[2] << 8) | p_rtp[3];
}

static inline uint32_t rtp_get_timestamp(const uint8_t *p_rtp)
{
    return (p_rtp[4] << 24) | (p_rtp[5] << 16) | (p_rtp[6] << 8) | p_rtp[7];
}

static inline uint8_t rtp_get_cc(const uint8_t *p_rtp)
{
    return p_rtp[0] & 0xf;
}

static inline void rtp_get_ssrc(const uint8_t *p_rtp, uint8_t pi_ssrc[4])
{
    pi_ssrc[0] = p_rtp[8];
    pi_ssrc[1] = p_rtp[9];
    pi_ssrc[2] = p_rtp[10];
    pi_ssrc[3] = p_rtp[11];
}

static inline uint8_t *rtp_extension(uint8_t *p_rtp)
{
    return p_rtp + RTP_HEADER_SIZE + 4 * rtp_get_cc(p_rtp);
}

static inline bool rtp_check_extension(const uint8_t *p_rtp)
{
    return !!(p_rtp[0] & 0x10);
}

static inline uint16_t rtpx_get_length(const uint8_t *p_rtpx)
{
    return (p_rtpx[2] << 8) | p_rtpx[3];
}

static inline uint8_t *rtp_payload(uint8_t *p_rtp)
{
    unsigned int i_size = RTP_HEADER_SIZE;
    i_size += 4 * rtp_get_cc(p_rtp);
    if (rtp_check_extension(p_rtp))
        i_size += 4 * (1 + rtpx_get_length(rtp_extension(p_rtp)));
    return p_rtp + i_size;
}

static inline bool ts_validate(const uint8_t *p_ts)
{
    return p_ts[0] == 0x47;
}

// </bitstream_functions> --------------------------------------------------------


/* Sequence number comparison with wrap-around */
static int seq_lt(uint16_t a, uint16_t b)
{
    return (int16_t)(a - b) < 0;
}

static int ts_le(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) <= 0;
}


static void rtp_build_header(unsigned char *hdr, uint16_t seq, uint32_t ts, uint32_t ssrc)
{
    hdr[0] = 0x80;           // Version 2, no padding, no extension
    hdr[1] = 33;             // Payload type 33 = MPEG-TS
    hdr[2] = seq >> 8;
    hdr[3] = seq & 0xff;
    hdr[4] = ts >> 24;
    hdr[5] = ts >> 16;
    hdr[6] = ts >> 8;
    hdr[7] = ts & 0xff;
    hdr[8] = ssrc >> 24;
    hdr[9] = ssrc >> 16;
    hdr[10] = ssrc >> 8;
    hdr[11] = ssrc & 0xff;
}


// SMPTE 2022-7 Receiver API --------------------------------------------------------

smpte_2022_7_rx_t *smpte_2022_7_rx_new(smpte_2022_7_rx_cb cb, void *user_data)
{
    smpte_2022_7_rx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->cb = cb;
    ctx->user_data = user_data;
    ctx->expected_seq = 0;
    ctx->last_ts = 0;
    return ctx;
}

int smpte_2022_7_rx_free(smpte_2022_7_rx_t *ctx)
{
    if (!ctx) return -1;
    for (int i = 0; i < ctx->buf_count; i++)
        free(ctx->buf[i].data);
    free(ctx);
    return 0;
}

static int smpte_2022_7_rx_buffer_erase(smpte_2022_7_rx_t *ctx, int index) {
    free(ctx->buf[index].data);
    ctx->buf_count--;
    memmove(&ctx->buf[index], &ctx->buf[index + 1], (ctx->buf_count - index) * sizeof(ctx->buf[0]));
    return 0;
}


int smpte_2022_7_rx_push_packet(smpte_2022_7_rx_t *ctx, int which, unsigned char *data, int len)
{
    (void)which; // we don’t actually care which leg this came from
    if (!ctx || !data || len < 4)
        return -1;

    uint16_t seq = rtp_get_seqnum(data);
    uint32_t ts = rtp_get_timestamp(data);

    if (ctx->initialized && seq_lt(seq, ctx->expected_seq)) {
        if (ts_le(ts, ctx->last_ts)) {
            LTN_DEBUG(&ctx->logger, "rx discarding seq=%d ts=%u last_ts=%u delta=%d", (int)seq, ts, ctx->last_ts, (int32_t)(ts - ctx->last_ts));
            /* 
             * This is too old of a sequence number / timestamp, drop it.
             * We need to consider both seq and ts to account for rollover times for high bitrate streams.
             */
            return 0;
        }
        else {
            LTN_DEBUG(&ctx->logger, "rx  retaining seq=%d ts=%u last_ts=%u delta=%d", (int)seq, ts, ctx->last_ts, (int32_t)(ts - ctx->last_ts));
        }
             
    }

    int min = -1;
    struct timespec tm, mintm;
    clock_gettime(CLOCK_MONOTONIC, &tm);
    memcpy(&mintm, &tm, sizeof(tm));

    // check if we already have this seq
    for (int i = 0; i < ctx->buf_count; i++) {
        struct pkt_entry *pkt = &ctx->buf[i];
        if (pkt->seq == seq)
            return 0; // duplicate packet, ignore
        if (ctx->buf_count >= 1024 && (mintm.tv_sec > pkt->tm.tv_sec || mintm.tv_nsec > pkt->tm.tv_nsec)) {
            mintm.tv_sec = pkt->tm.tv_sec;
            mintm.tv_nsec = pkt->tm.tv_nsec;
            min = i;
        }
    }

    if (ctx->buf_count >= 1024) {
        if (min >= 0) {                    
            smpte_2022_7_rx_buffer_erase(ctx, min);
        }
        else return -1; // buffer full
    }

    // store packet
    struct pkt_entry *pkt = &ctx->buf[ctx->buf_count];
    pkt->seq = seq;
    pkt->ts = ts;
    pkt->len = len;
    pkt->data = malloc(len);
    memcpy(pkt->data, data, len);
    memcpy(&pkt->tm, &tm, sizeof(tm));    
    ctx->buf_count++;
    
    if (!ctx->initialized) {
        ctx->expected_seq = ctx->buf[0].seq;
        ctx->last_ts = ctx->buf[0].ts - 1;
        ctx->initialized = true;
    }

    // try to flush in order
    int flushed = 0;
    while (1) {
        int found = -1;
        for (int i = 0; i < ctx->buf_count; i++) {
            if (ctx->buf[i].seq == ctx->expected_seq) {
                found = i;
                break;
            }
        }

        if (found < 0)
            break; // next expected not yet received

        // deliver
        
        ctx->cb(ctx->user_data, ctx->buf[found].data, ctx->buf[found].len);
        flushed++;
        LTN_DEBUG(&ctx->logger, "rx seq=%06d, tx seq=%06d, flushed=%d, index=%d/%d", (int)seq, (int)ctx->expected_seq, flushed, found, ctx->buf_count);
        
        ctx->last_ts = ctx->buf[found].ts;

        smpte_2022_7_rx_buffer_erase(ctx, found);
        
        ctx->expected_seq++;
    }

    return flushed;
}

int smpte_2022_7_rx_push_packets(smpte_2022_7_rx_t *ctx, int which, unsigned char *data, int len)
{
    errno = 0;
    unsigned char *p = data, *end = data + len;
    int i = 0;
    while (p + 4 < end) {
        // TODO: put the right pts as last param. is pid_stats available???			
        if (rtp_check_hdr(p) && rtp_get_type(p) == 33) {
            unsigned char *next = rtp_payload(p);
            while (next < end && ts_validate(next)) next += TS_PACKET_SIZE;

            int rc = smpte_2022_7_rx_push_packet(ctx, 0, p, next - p);            
            uint8_t ssrc[16];
            rtp_get_ssrc(p, ssrc);
            LTN_DEBUG(&ctx->logger, "push written=%02d seq=%06d ssrc=%02hx%02hx%02hx%02hx ts=%d", rc, (int)rtp_get_seqnum(p), ssrc[0], ssrc[1], ssrc[2], ssrc[3], rtp_get_timestamp(p));
            p = next;
            ++i;
        }
        else {
            LTN_ERROR(&ctx->logger, "Received unexpected byte sequence, droping %d bytes", (end - p));
            errno = EILSEQ;
            return p - data;
        }
    }
    if (p < end) {
        LTN_WARN(&ctx->logger, "Dangling bytes: %d", end - p);        
        return p - data;
    }

    return len;
}

int smpte_2022_7_rx_set_logger(smpte_2022_7_rx_t *ctx, const struct ltntstools_logger_s *logger) {
    memcpy(&ctx->logger, logger, sizeof(struct ltntstools_logger_s));
    return 0;
}


// SMPTE 2022-7 Transmitter API -------------------------------------------------------------------


smpte_2022_7_tx_t *smpte_2022_7_tx_new(smpte_2022_7_tx_cb cb, void *user_data, int legs)
{
    if (!cb)
        return NULL;

    smpte_2022_7_tx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->cb = cb;
    ctx->seq = 0;
    ctx->payload_len = 0;
    ctx->user_data = user_data;
    ctx->num_legs = legs;

    return ctx;
}

int smpte_2022_7_tx_free(smpte_2022_7_tx_t *ctx)
{
    if (!ctx)
        return -1;
    free(ctx);
    return 0;
}

static int min(int a, int b) { return a < b ? a : b; }
static int max(int a, int b) { return a > b ? a : b; }

int smpte_2022_7_tx_push_packets(smpte_2022_7_tx_t *ctx, unsigned char *data, int len, uint32_t *ts)
{
    if (!ctx || !data || len <= 0)
        return -1;
    
    unsigned char *p = data;
    unsigned char *end = data + len;
    while (p < end) {
        int to_copy = max(0, min(RTP_PAYLOAD_SIZE - ctx->payload_len, end - p));
        memcpy(ctx->buffer + RTP_HEADER_SIZE + ctx->payload_len, p, to_copy);
        p += to_copy;
        ctx->payload_len += to_copy;

        if (ctx->payload_len >= RTP_PAYLOAD_SIZE) {
            struct timespec tm;
            clock_gettime(CLOCK_MONOTONIC, &tm);
            uint32_t _ts = (uint32_t)((uint32_t)(27000000 * tm.tv_sec) + (uint32_t)(0.027 * tm.tv_nsec));

            for (int leg = 0; leg < ctx->num_legs; ++leg) {
                uint32_t ssrc = 0x4c544e00 + leg;
                rtp_build_header(ctx->buffer, ctx->seq, _ts, ssrc);                
                ctx->cb(ctx->user_data, leg, ctx->buffer, RTP_MAX_PACKET_SIZE);
            }
            ++ctx->seq;
            ctx->payload_len = 0;
        }
    }

    return end - p;
}

int smpte_2022_7_tx_set_logger(smpte_2022_7_tx_t *ctx, const struct ltntstools_logger_s *logger) {
    memcpy(&ctx->logger, logger, sizeof(struct ltntstools_logger_s));
    return 0;
}
