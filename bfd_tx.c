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
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>

static int use_txtime = 0;
static uint64_t txtime_lead_ns = 5000000;
static uint64_t pipe_until = 0;

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

static int use_ktx = 0;
static int ktx_ifindex = 0;
static int tx_cfg_fd = -1, sess_map_fd = -1;
struct skey { uint32_t peer_ip, local_ip; };
static struct skey skey;
struct scfg { uint32_t enable, my_disc, your_disc, min_tx_us, min_rx_us;
              uint8_t state, diag, mult, pad; };
struct sstate { uint64_t last_seen_ns, rx_pkts;
                uint32_t remote_disc, local_disc, min_tx_us, min_rx_us;
                uint8_t remote_state, remote_diag, detect_mult, alive; };
   /* enqueue 5ms early */


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
    if (argc >= 4 && !strcmp(argv[3], "--txtime")) use_txtime = 1;
    if (argc >= 5 && !strcmp(argv[3], "--kernel-tx")) {
        use_ktx = 1;
        ktx_ifindex = if_nametoindex(argv[4]);
        if (!ktx_ifindex) { perror("ifname"); return 1; }
    }
    if (argc < 3) { fprintf(stderr,"usage: %s <local-ip> <peer-ip> [--txtime]\n",argv[0]); return 1; }

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

    if (use_ktx) {
        struct bpf_object *obj = bpf_object__open_file("bfd_xdp.o", NULL);
        if (!obj || bpf_object__load(obj)) {
            fprintf(stderr, "bfd_xdp.o load failed\n"); return 1;
        }
        struct bpf_program *pr =
            bpf_object__find_program_by_name(obj, "bfd_observer");
        if (bpf_xdp_attach(ktx_ifindex, bpf_program__fd(pr),
                           XDP_FLAGS_DRV_MODE, NULL)) {
            fprintf(stderr, "XDP attach failed (is bfd_loader running?)\n");
            return 1;
        }
        tx_cfg_fd   = bpf_object__find_map_fd_by_name(obj, "tx_config");
        sess_map_fd = bpf_object__find_map_fd_by_name(obj, "bfd_sessions");
        inet_pton(AF_INET, argv[2], &skey.peer_ip);
        inet_pton(AF_INET, argv[1], &skey.local_ip);
        printf("bfd_tx: kernel-tx mode, XDP attached\n");
    }

    if (use_txtime) {
        struct sock_txtime st = { .clockid = CLOCK_TAI, .flags = 0 };
        if (setsockopt(tx, SOL_SOCKET, SO_TXTIME, &st, sizeof st)) {
            perror("SO_TXTIME"); return 1;
        }
        printf("bfd_tx: SO_TXTIME mode, lead=%.1fms\n", txtime_lead_ns/1e6);
    }

    srandom(getpid() ^ time(NULL));
    uint32_t my_disc = (random() & 0x7fffffff) | 1;

    int      state = ST_DOWN, diag = 0;
    uint32_t rdisc = 0;
    int      rstate = ST_DOWN; (void)rstate;
    uint32_t r_min_rx = 0, r_min_tx = 0;
    int      r_mult = 0;
    int      send_final = 0;
    int      just_up = 0;
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
                just_up = (state == ST_UP);
                printf("[%llu] %s -> %s (peer sent %s)\n",
                       (unsigned long long)now_us(),
                       stname[old], stname[state], stname[ps]);
                next_tx = now_us();          /* speak up immediately */
                pipe_until = 0;
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

        if (use_ktx) {
            static int pushed_state = -1;
            struct sstate ss;
            if (state == ST_UP &&
                bpf_map_lookup_elem(sess_map_fd, &skey, &ss) == 0) {
                if (ss.last_seen_ns/1000 > last_rx)
                    last_rx = ss.last_seen_ns/1000;
                if (ss.remote_state == ST_DOWN) {
                    printf("[%llu] Up -> Down (map: peer sent Down)\n",
                           (unsigned long long)now_us());
                    state = ST_DOWN; diag = 3;
                    next_tx = now_us();
                }
            }
            if (state != pushed_state) {
                struct scfg c = {
                    .enable = (state == ST_UP),
                    .my_disc = my_disc, .your_disc = rdisc,
                    .min_tx_us = MIN_TX_US, .min_rx_us = MIN_RX_US,
                    .state = state, .diag = diag, .mult = DETECT_MULT,
                };
                bpf_map_update_elem(tx_cfg_fd, &skey, &c, 0);
                pushed_state = state;
            }
        }

        /* ---- detect timeout ---- */
        if (state != ST_DOWN && last_rx) {
            uint64_t iv = r_min_tx > MIN_RX_US ? r_min_tx : MIN_RX_US;
            int64_t sdelta = (int64_t)(t - last_rx);
            if (sdelta < 0) sdelta = 0;   /* map stamped newer than our t snapshot */
            if ((uint64_t)sdelta > (uint64_t)(r_mult ? r_mult : DETECT_MULT) * iv) {
                printf("[%llu] DETECT TIMEOUT: %s -> Down (silent %.1fms)\n",
                       (unsigned long long)t, stname[state],
                       (t - last_rx)/1000.0);
                state = ST_DOWN; diag = 1; rdisc = 0;
            }
        }

        /* ---- TX ---- */
        if ((t >= next_tx || send_final) && !(use_ktx && state == ST_UP && !send_final && !just_up)) {
            struct bfdpkt o = {0};
            o.vers_diag = (1<<5) | (diag & 0x1f);
            o.flags     = (state<<6) | (send_final ? F_F : 0);
            o.mult      = DETECT_MULT;
            o.len       = 24;
            o.my_disc   = htonl(my_disc);
            o.your_disc = htonl(rdisc);
            o.min_tx    = htonl(state==ST_UP ? MIN_TX_US : SLOW_TX_US);
            o.min_rx    = htonl(MIN_RX_US);
            if (!use_txtime) {
                send(tx, &o, 24, 0);
            } else {
                struct timespec rt; clock_gettime(CLOCK_TAI, &rt);
                uint64_t now_tai = (uint64_t)rt.tv_sec*1000000000ull + rt.tv_nsec;
                uint64_t min_launch = now_tai + txtime_lead_ns;
                uint64_t iv_ns = (uint64_t)(MIN_TX_US > r_min_rx ? MIN_TX_US : r_min_rx) * 1000ull;
                char cbuf[CMSG_SPACE(sizeof(uint64_t))];
                struct iovec iov = { .iov_base = &o, .iov_len = 24 };
                struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1,
                                     .msg_control = cbuf,
                                     .msg_controllen = sizeof cbuf };
                struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
                cm->cmsg_level = SOL_SOCKET;
                cm->cmsg_type  = SCM_TXTIME;
                cm->cmsg_len   = CMSG_LEN(sizeof(uint64_t));

                if (state != ST_UP || send_final) {
                    /* urgent or handshake: launch ASAP, drop pipeline */
                    memcpy(CMSG_DATA(cm), &min_launch, sizeof min_launch);
                    if (sendmsg(tx, &mh, 0) < 0) perror("sendmsg txtime");
                    pipe_until = 0;
                } else {
                    /* steady Up: top the etf queue up to 5 intervals,
                     * send nothing if already full (no cursor drift) */
                    if (pipe_until < min_launch) pipe_until = min_launch;
                    while (pipe_until < now_tai + 5*iv_ns) {
                        uint64_t launch = pipe_until;
                        memcpy(CMSG_DATA(cm), &launch, sizeof launch);
                        if (sendmsg(tx, &mh, 0) < 0) perror("sendmsg txtime");
                        pipe_until = launch + iv_ns;
                    }
                }
            }
            printf("TX st=%d f=%02x\n", state, o.flags);
            send_final = 0;
            just_up = 0;

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
