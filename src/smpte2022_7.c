#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <arpa/inet.h>
#include <limits.h>

#include "libltntstools/smpte2022_7.h"

#define TS_PACKET_SIZE      188
#define TS_PER_RTP_PACKET   7
#define RTP_PAYLOAD_SIZE    (TS_PACKET_SIZE * TS_PER_RTP_PACKET)
#define RTP_HEADER_SIZE     12
#define RTP_MAX_PACKET_SIZE (RTP_HEADER_SIZE + RTP_PAYLOAD_SIZE)
#define MAX_LEGS            3
#define MAX_PACKET_BACKLOG  10 * 1024 * 1024


struct pkt_entry {
    uint16_t seq;
    uint32_t ts;
    int len;
    unsigned char *data;
    struct timespec tm;
};

typedef struct {
    bool seen;
    bool ready;
    uint16_t seq;
    uint32_t timestamp;
    struct timespec tm;
    uint64_t byte_count;
} leg_stats_t;

struct smpte_2022_7_rx_s {
    // callback stuff
    smpte_2022_7_rx_cb cb;
    void *user_data;    

    // buffer stuff
    struct pkt_entry *buf, *tip;
    int buf_count;
    int buf_capacity;
    
    // tracking
    uint16_t expected_seq;
    uint32_t last_ts;

    // classification
    uint8_t legs;
    char receiver_class;

    // initialization
    leg_stats_t leg_stats[MAX_LEGS];
    struct timespec first_packet_time;
    bool initialized;
    bool all_seen;

    // logging
    int verbose;
    struct ltntstools_logger_s logger;
};


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

#define UINT32_HALF (UINT32_MAX >> 1)


static int seq_le(uint16_t a, uint16_t b)
{
    return (int16_t)(a - b) <= 0;
}

static int seq_gt(uint16_t a, uint16_t b)
{
    return !seq_le(a, b);
}

/* Sequence number comparison with wrap-around */
static int seq_lt(uint16_t a, uint16_t b)
{
    return (int16_t)(a - b) < 0;
}

static int ts_le(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) <= 0; //  && (b - a) < UINT32_HALF;
}


static int ts_gt(uint32_t a, uint32_t b)
{
    return !ts_le(a, b);
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

smpte_2022_7_rx_t *smpte_2022_7_rx_new(smpte_2022_7_rx_cb cb, void *user_data, uint8_t legs, char receiver_class)
{    
    if (legs > MAX_LEGS) {
        // LTN_ERROR(&ctx->logger, "%s(): legs=%hhu exceeds max=%d", __func__, legs, MAX_LEGS);
        errno = EINVAL;
        return NULL;
    }

    receiver_class = toupper(receiver_class);
    if (receiver_class < 'A' || receiver_class > 'D') {
        // LTN_ERROR(&ctx->logger, "%s(): receiver_class=%c, valid values A,B,C,D, __func__, receiver_class);
        errno = EINVAL;
        return NULL;
    }

    smpte_2022_7_rx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->buf_capacity = 1024;
    ctx->buf = calloc(ctx->buf_capacity, sizeof(struct pkt_entry));
    if (!ctx->buf) {
        free(ctx);
        return NULL;
    }
    
    ctx->cb = cb;
    ctx->user_data = user_data;
    ctx->receiver_class = receiver_class;
    ctx->expected_seq = 0;
    ctx->last_ts = 0;
    ctx->legs = legs;
    return ctx;
}

int smpte_2022_7_rx_free(smpte_2022_7_rx_t *ctx)
{
    if (!ctx) return -1;
    for (int i = 0; i < ctx->buf_count; i++)
        free(ctx->buf[i].data);
    free(ctx->buf);
    free(ctx);
    return 0;
}

static int smpte_2022_7_rx_buffer_erase(smpte_2022_7_rx_t *ctx, int index) {
    free(ctx->buf[index].data);
    ctx->buf_count--;
    memmove(&ctx->buf[index], &ctx->buf[index + 1], (ctx->buf_count - index) * sizeof(ctx->buf[0]));
    return 0;
}

static int smpte_2022_7_rx_check_init(smpte_2022_7_rx_t *ctx, int which) {
    if (ctx->initialized) return 0;

    leg_stats_t *stats = &ctx->leg_stats[which];

    if (!ctx->first_packet_time.tv_sec && !ctx->first_packet_time.tv_nsec) {
        // this is the first packet we're seeing, record the timestamp.
        memcpy(&ctx->first_packet_time, &stats->tm, sizeof(ctx->first_packet_time));
    }
    
    if (!ctx->all_seen) {
        if (!stats->seen) {
            LTN_INFO(&ctx->logger, "Found leg %d at seq=%d", which, stats->seq);
        }
        
        stats->seen = true;

        bool all_seen = true;
        leg_stats_t *most_advanced = &ctx->leg_stats[0];

        // find the highest sequence number (considering wraparound). this will be our starting position to measure PD.
        for (int i = 0; i < ctx->legs; ++i) {
            leg_stats_t *leg = &ctx->leg_stats[i];
            all_seen = all_seen && leg->seen;
            if (i && seq_lt(most_advanced->seq, leg->seq))
                most_advanced = leg;
        }

        if (all_seen) {            
            ctx->all_seen = true;
            // reset the first-packet time based on this most-advanced packet, we'll count from here.
            memcpy(&ctx->first_packet_time, &stats->tm, sizeof(ctx->first_packet_time));
            
            most_advanced->ready = true;

            // record what we're looking out for
            ctx->expected_seq = most_advanced->seq;
            ctx->last_ts = stats->timestamp - 1;
            while (ctx->buf_count > 0) {
                if (ctx->buf[0].seq == ctx->expected_seq && ctx->buf[0].ts == most_advanced->timestamp) {
                    break;
                }
                smpte_2022_7_rx_buffer_erase(ctx, 0);
            }
            LTN_INFO(&ctx->logger, "All %d legs seen, watching for seq=%hu on all legs", ctx->legs, ctx->expected_seq);
        }
    }
    else {
        // 2 cases to handle:

        // 1. Sequence waiting (preferred)
        bool all_ready = true;
        struct timespec *latest = NULL;
        for (int i = 0; i < ctx->legs; ++i) {
            leg_stats_t *leg = &ctx->leg_stats[i];
            if (!leg->ready && seq_le(ctx->expected_seq, leg->seq)) {
                leg->ready = true;
                latest = &leg->tm;
            }
            all_ready = all_ready && leg->ready;
        }

        uint64_t diff;
        if (all_ready && latest) {
            diff = (latest->tv_sec - ctx->first_packet_time.tv_sec) * 1000000 + (latest->tv_nsec - ctx->first_packet_time.tv_nsec) / 1000;
            // LTN_INFO(&ctx->logger, "instantaneous path differential, PD=%.3fms", diff / 1000.);
            // ctx->initialized = true; // TODO: keep acruing to max of class.
            // return 0;
        }

        // 2. Time-based worst-case, based on receiver class (fallback or fatal)

        uint64_t diff_us = (stats->tm.tv_sec - ctx->first_packet_time.tv_sec) * 1000000 + (stats->tm.tv_nsec - ctx->first_packet_time.tv_nsec) / 1000;        
        uint64_t target = 0;
        switch (ctx->receiver_class) {
        case 'A':
            target = 10000;
            break; 
        case 'B':
            target = 50000;
            break;
        case 'C':
            target = 450000;
            break;
        case 'D':
            target = 150;
            break;
        }
        double diff_percent = (1.0 * diff_us)/target;
        if (diff_percent < 1 && diff_percent > .95) {
            if (!all_ready) {
                LTN_INFO(&ctx->logger, "PD=%.3fms requirement for a class '%c' receiver! All bets are off!", target / 1000., ctx->receiver_class);
            }
            else {
                LTN_INFO(&ctx->logger, "Initialization complete! Receiver class '%c', MD=%.3fms", ctx->receiver_class, diff_us / 1000.);
            }
            ctx->initialized = true;
        }
        else if (all_ready && latest) {
            LTN_INFO(&ctx->logger, "PD=%.3fms requirement=%.3fms for a class '%c' receiver.", diff_us / 1000., target / 1000., ctx->receiver_class);
        }
    }
}


int smpte_2022_7_rx_push_packet(smpte_2022_7_rx_t *ctx, int which, unsigned char *data, int len)
{   
    if (!ctx || !data || len < 4)
        return -1;

    leg_stats_t *stats = &ctx->leg_stats[which];

    stats->seq = rtp_get_seqnum(data);
    stats->timestamp = rtp_get_timestamp(data);
    stats->byte_count += len;
    clock_gettime(CLOCK_MONOTONIC, &stats->tm);

    if (!ctx->initialized && smpte_2022_7_rx_check_init(ctx, which) < 0) {
        return -1;
    }

    struct pkt_entry *tip = NULL;
    if (ctx->buf_count > 0) {
        tip = &ctx->buf[ctx->buf_count - 1];
    }
    
    // This is too old of a sequence number / timestamp, drop it.
    // We need to consider both seq and ts to account for rollover times for high bitrate streams.
    bool discard = true;

    if (!tip || (seq_gt(stats->seq, tip->seq) && ts_gt(stats->timestamp, tip->ts))) {
        // this is the most likely scenario, and cheapest to evaluate
        discard = false;
    }
    else {
        for (int i = ctx->buf_count - 1; i >= 0; --i) {
            struct pkt_entry *pkt = &ctx->buf[i];
            if (stats->seq == pkt->seq && stats->timestamp == pkt->ts) {
                discard = true;
                break;
            }
            // TODO: else {...} for optimization?
        }
    }

    if (discard) {
        LTN_DEBUG(&ctx->logger, "rx discarding leg=%d seq=%d pseq=%d ts=%u last_ts=%u delta=%d",
            which, (int)stats->seq, (int)(tip ? tip->seq: -1), stats->timestamp, tip ? tip->ts: 0, (int32_t)(stats->timestamp - ctx->last_ts));
        return 0;
    }

    // store packet

    if (ctx->buf_count >= ctx->buf_capacity) {
        // TODO: review this, maybe switch to circular buffer for performance
        if (!ctx->initialized) {
            if (ctx->buf_capacity > MAX_PACKET_BACKLOG) {
                LTN_ERROR(&ctx->logger, "Max buffer capacity exceeded");
                errno = ENOBUFS;
                return -1;
            }

            ctx->buf_capacity *= 2;
            ctx->buf = realloc(ctx->buf, ctx->buf_capacity);
        }
        else {
            LTN_ERROR(&ctx->logger, "Max buffer capacity exceeded");
            errno = ENOBUFS;
            return -1;
        }
    }

    struct pkt_entry *pkt = &ctx->buf[ctx->buf_count];
    pkt->seq = stats->seq;
    pkt->ts = stats->timestamp;
    pkt->len = len;
    pkt->data = malloc(len);
    memcpy(pkt->data, data, len);
    memcpy(&pkt->tm, &stats->tm, sizeof(stats->tm));
    ctx->buf_count++;

    uint8_t ssrc[16];
    rtp_get_ssrc(pkt->data, ssrc);

    LTN_DEBUG(&ctx->logger, "admit seq=%06d ts=%u ssrc=%02hx%02hx%02hx%02hx, tip_seq=%06d, ts=%u",
        (int)stats->seq, stats->timestamp, ssrc[0], ssrc[1], ssrc[2], ssrc[3],
        (int) (tip ? tip->seq : -1), (unsigned int)(tip ? tip->ts : 0));

    // we're still acruing, don't let anything out the door.
    if (!ctx->initialized) return 0;

    // try to flush in order
    int flushed = 0;
    while (1) {
        int found = -1;
        for (int i = 0; i < ctx->buf_count; i++) {
            if (ctx->buf[i].seq == ctx->expected_seq && ts_le(ctx->last_ts, ctx->buf[i].ts)) {
                found = i;
                break;
            }
        }

        if (found < 0)
            break; // next expected not yet received

        // deliver
        
        ctx->cb(ctx->user_data, ctx->buf[found].data, ctx->buf[found].len);
        flushed++;
        rtp_get_ssrc(ctx->buf[found].data, ssrc);
        LTN_DEBUG(&ctx->logger, "rx seq=%06d ts=%u, tx seq=%06d ts=%u, ssrc=%02hx%02hx%02hx%02hx index=%d/%d",
            (int)stats->seq, stats->timestamp,
            (int)ctx->expected_seq, ctx->buf[found].ts,
            ssrc[0], ssrc[1], ssrc[2], ssrc[3],
            found, ctx->buf_count);

        ctx->last_ts = ctx->buf[found].ts;

        smpte_2022_7_rx_buffer_erase(ctx, found);
        
        ctx->expected_seq++;
        break;
    }

    if (!flushed) {
        LTN_DEBUG(&ctx->logger, "no bytes written on arrival of leg=%d seq=%06d ts=%u",
            which, (int)rtp_get_seqnum(data), rtp_get_timestamp(data));
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

            int rc = smpte_2022_7_rx_push_packet(ctx, which, p, next - p);
            if (rc < 0) return rc;
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
