// SPDX-License-Identifier: GPL-2.0
/* bfd_tx.c - minimal userspace BFD endpoint (RFC 5880/5881 subset).
 * Single session, single-hop, active mode, no auth/echo/demand.
 * Usage: sudo ./bfd_tx <local-ip> <peer-ip>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define PORT_CTRL   3784
#define SRC_PORT    49152        /* RFC 5881: source in 49152..65535 */
#define MIN_TX_US   10000
#define MIN_RX_US   10000
#define DETECT_MULT 3
#define SLOW_TX_US  1000000      /* >=1s while session not Up */

enum { ST_ADMINDOWN, ST_DOWN, ST_INIT, ST_UP };
static const char *stname[] = {"AdminDown","Down","Init","Up"};

struct bfdpkt {
    uint8_t  vers_diag, flags, mult, len;
    uint32_t my_disc, your_disc, min_tx, min_rx, min_echo;
} __attribute__((packed));

#define F_P 0x20
#define F_F 0x10

static uint64_t now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000000ull + ts.tv_nsec/1000;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr,"usage: %s <local-ip> <peer-ip>\n",argv[0]); return 1; }

    /* RX socket: bind <local-ip>:3784 */
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in la = { .sin_family=AF_INET, .sin_port=htons(PORT_CTRL) };
    inet_pton(AF_INET, argv[1], &la.sin_addr);
    if (bind(rx,(void*)&la,sizeof la)) { perror("bind 3784 (is bfdd still running?)"); return 1; }
    struct timeval tv = { .tv_usec = 2000 };            /* 2ms RX poll tick */
    setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* TX socket: source port 49152, TTL 255, connected to peer:3784 */
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    int ttl = 255;
    setsockopt(tx, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl);
    struct sockaddr_in sa = la; sa.sin_port = htons(SRC_PORT);
    if (bind(tx,(void*)&sa,sizeof sa)) { perror("bind src"); return 1; }
    struct sockaddr_in pa = { .sin_family=AF_INET, .sin_port=htons(PORT_CTRL) };
    inet_pton(AF_INET, argv[2], &pa.sin_addr);
    connect(tx,(void*)&pa,sizeof pa);

    srandom(getpid() ^ time(NULL));
    uint32_t my_disc = (random() & 0x7fffffff) | 1;

    int      state = ST_DOWN, diag = 0;
    uint32_t rdisc = 0;
    int      rstate = ST_DOWN; (void)rstate;
    uint32_t r_min_rx = 0, r_min_tx = 0;
    int      r_mult = 0;
    int      send_final = 0;
    uint64_t last_rx = 0, next_tx = now_us();

    printf("bfd_tx: disc=%u %s -> %s\n", my_disc, argv[1], argv[2]);

    for (;;) {
        /* ---- RX ---- */
        struct bfdpkt p;
        ssize_t n = recv(rx, &p, sizeof p, 0);
        if (n >= 24 && ((p.vers_diag>>5)&7)==1 && p.mult && p.my_disc) {
            int ps = (p.flags>>6)&3;
            rdisc   = ntohl(p.my_disc);
            rstate  = ps;
            r_min_rx= ntohl(p.min_rx);
            r_min_tx= ntohl(p.min_tx);
            r_mult  = p.mult;
            last_rx = now_us();
            if (p.flags & F_P) send_final = 1;   /* answer Poll with Final */

            int old = state;
            if (ps == ST_ADMINDOWN) {
                if (state != ST_DOWN) { state = ST_DOWN; diag = 3; }
            } else switch (state) {
            case ST_DOWN:
                if (ps == ST_DOWN)      state = ST_INIT;
                else if (ps == ST_INIT) state = ST_UP;
                break;
            case ST_INIT:
                if (ps == ST_INIT || ps == ST_UP) state = ST_UP;
                break;
            case ST_UP:
                if (ps == ST_DOWN) { state = ST_DOWN; diag = 3; }
                break;
            }
            if (state != old) {
                printf("[%llu] %s -> %s (peer sent %s)\n",
                       (unsigned long long)now_us(),
                       stname[old], stname[state], stname[ps]);
                next_tx = now_us();          /* speak up immediately */
            }
        }

        uint64_t t = now_us();

        /* re-clamp TX schedule if the negotiated interval shrank
         * (e.g. peer moved from slow Down-state timers to fast Up timers) */
        if (last_rx) {
            uint64_t cur_iv = (state == ST_UP)
                ? (MIN_TX_US > r_min_rx ? MIN_TX_US : r_min_rx)
                : SLOW_TX_US;
            if (next_tx > t + cur_iv)
                next_tx = t + cur_iv;
        }

        /* ---- detect timeout ---- */
        if (state != ST_DOWN && last_rx) {
            uint64_t iv = r_min_tx > MIN_RX_US ? r_min_tx : MIN_RX_US;
            if (t - last_rx > (uint64_t)(r_mult ? r_mult : DETECT_MULT) * iv) {
                printf("[%llu] DETECT TIMEOUT: %s -> Down (silent %.1fms)\n",
                       (unsigned long long)t, stname[state],
                       (t - last_rx)/1000.0);
                state = ST_DOWN; diag = 1; rdisc = 0;
            }
        }

        /* ---- TX ---- */
        if (t >= next_tx || send_final) {
            struct bfdpkt o = {0};
            o.vers_diag = (1<<5) | (diag & 0x1f);
            o.flags     = (state<<6) | (send_final ? F_F : 0);
            o.mult      = DETECT_MULT;
            o.len       = 24;
            o.my_disc   = htonl(my_disc);
            o.your_disc = htonl(rdisc);
            o.min_tx    = htonl(state==ST_UP ? MIN_TX_US : SLOW_TX_US);
            o.min_rx    = htonl(MIN_RX_US);
            send(tx, &o, 24, 0); printf("TX st=%d f=%02x\n", state, o.flags);
            send_final = 0;

            uint64_t iv;
            if (state == ST_UP) {
                iv = MIN_TX_US > r_min_rx ? MIN_TX_US : r_min_rx;
                iv = iv*3/4 + (random() % (iv/4 + 1));   /* 75-100% jitter */
            } else {
                iv = SLOW_TX_US;
            }
            if (t >= next_tx) next_tx = t + iv;
        }
    }
    return 0;
}
