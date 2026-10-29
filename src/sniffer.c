/*
 * sniffer.c — Raw packet capture and header parsing.
 *
 * An AF_PACKET socket opened with ETH_P_IP hands us every incoming IPv4
 * frame; we walk link → IP → TCP/UDP and report the ones aimed at a knock
 * port. Every offset is bounds-checked against the number of bytes we
 * actually received, because the frames are attacker-controlled.
 */

#include "sniffer.h"
#include "config.h"
#include "logger.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>        /* if_nametoindex() */
#include <net/if_arp.h>    /* ARPHRD_ETHER, ARPHRD_LOOPBACK */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Big enough for a jumbo frame. */
#define PKT_BUF_SIZE 65536

/*
 * How long recvfrom() blocks before reporting SNIFFER_AGAIN.
 *
 * Without a timeout the capture thread could sit in recvfrom() forever on
 * a quiet network. A signal is not a reliable wake-up: it may be delivered
 * to whichever thread the kernel picks, so the one actually blocked here
 * might never see it, and shutdown would hang waiting to join it.
 */
#define RECV_TIMEOUT_US 250000

/* Set from KNOCK_INTERFACE at init; 0 means capture on every interface. */
static unsigned int g_ifindex = 0;

/*
 * Is this one of the configured knock ports?
 */
static int is_knock_port(uint16_t port)
{
    for (int i = 0; i < KNOCK_SEQ_LEN; i++) {
        if (KNOCK_SEQUENCE[i] == port) {
            return 1;
        }
    }
    return 0;
}

/*
 * Work out where the IP header starts.
 *
 * SOCK_RAW hands us the link-layer header, and its size depends on the
 * interface: 14 bytes on Ethernet and loopback, but nothing at all on
 * point-to-point tunnels (WireGuard, OpenVPN, PPP), where skipping 14
 * bytes regardless would have us parse the middle of the IP header as if
 * it were the start. The result is checked against the IP version and
 * header-length fields, so an interface type we guessed wrong about makes
 * us drop the packet rather than read nonsense.
 *
 * Returns 0 and stores the offset on success, -1 if this is not a frame we
 * can parse.
 */
static int find_ip_offset(const unsigned char *buf, size_t len,
                          unsigned short hatype, size_t *offset)
{
    size_t              ip_off;
    const struct iphdr *iph;

    switch (hatype) {
        case ARPHRD_ETHER:
        case ARPHRD_LOOPBACK:
            if (len < sizeof(struct ethhdr)) {
                return -1;
            }
            if (ntohs(((const struct ethhdr *)buf)->h_proto) != ETH_P_IP) {
                return -1;
            }
            ip_off = sizeof(struct ethhdr);
            break;
        default:
            /* Assume the frame starts with the IP header. */
            ip_off = 0;
            break;
    }

    if (len < ip_off + sizeof(struct iphdr)) {
        return -1;
    }

    iph = (const struct iphdr *)(buf + ip_off);
    if (iph->version != 4 || iph->ihl < 5) {
        return -1;
    }

    *offset = ip_off;
    return 0;
}

/* ── Public API ──────────────────────────────────────────────────────── */

int sniffer_init(void)
{
    struct timeval tv;
    int            sock;

    /*
     * AF_PACKET + SOCK_RAW receives raw frames; ETH_P_IP narrows that to
     * IPv4, so ARP and IPv6 never reach userspace. Requires CAP_NET_RAW.
     */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) {
        log_error("Failed to create raw socket: %s", strerror(errno));
        if (errno == EPERM || errno == EACCES) {
            log_error("Raw sockets need root or CAP_NET_RAW. Try sudo.");
        }
        return -1;
    }

    tv.tv_sec  = 0;
    tv.tv_usec = RECV_TIMEOUT_US;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        /*
         * Not fatal for capture, but shutdown then depends on a signal
         * reaching this thread, so say so rather than hanging silently.
         */
        log_warn("Could not set a receive timeout on the raw socket (%s) "
                 "— shutdown may take longer", strerror(errno));
    }

    if (KNOCK_INTERFACE[0] != '\0') {
        g_ifindex = if_nametoindex(KNOCK_INTERFACE);
        if (g_ifindex == 0) {
            log_error("Unknown interface '%s': %s",
                      KNOCK_INTERFACE, strerror(errno));
            close(sock);
            return -1;
        }
        log_info("Capturing on %s only", KNOCK_INTERFACE);
    } else {
        log_debug("Capturing on every interface");
    }

    log_debug("Raw socket created (fd %d)", sock);
    return sock;
}

int sniffer_next_knock(int sock_fd, uint32_t *src_ip, uint16_t *dst_port)
{
    unsigned char buffer[PKT_BUF_SIZE];

    for (;;) {
        struct sockaddr_ll  sll;
        socklen_t           sll_len = sizeof(sll);
        const struct iphdr *iph;
        size_t              ip_offset;
        size_t              ip_hdr_len;
        size_t              l4_offset;
        ssize_t             pkt_len;
        uint16_t            dport;
        const char         *proto_name;

        pkt_len = recvfrom(sock_fd, buffer, sizeof(buffer), 0,
                           (struct sockaddr *)&sll, &sll_len);
        if (pkt_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return SNIFFER_AGAIN;
            }
            log_error("recvfrom() failed: %s", strerror(errno));
            return SNIFFER_ERROR;
        }

        /*
         * Defensive clamp. Every bounds check below compares against
         * pkt_len, so the parsing is only safe while pkt_len describes
         * bytes we actually hold.
         */
        if ((size_t)pkt_len > sizeof(buffer)) {
            pkt_len = (ssize_t)sizeof(buffer);
        }

        /*
         * Skip traffic this host is sending. A packet socket sees both
         * directions, so an outbound connection from this machine to
         * someone else's port 7000 would otherwise be recorded as a knock
         * from our own address.
         */
        if (sll.sll_pkttype == PACKET_OUTGOING) {
            continue;
        }

        if (g_ifindex != 0 && (unsigned int)sll.sll_ifindex != g_ifindex) {
            continue;
        }

        if (find_ip_offset(buffer, (size_t)pkt_len, sll.sll_hatype,
                           &ip_offset) != 0) {
            continue;
        }

        iph        = (const struct iphdr *)(buffer + ip_offset);
        ip_hdr_len = (size_t)iph->ihl * 4;

        /* An IPv4 header is 20–60 bytes; find_ip_offset() checked the
         * lower bound, this checks that it is really there. */
        if (ip_offset + ip_hdr_len > (size_t)pkt_len) {
            continue;
        }

        /*
         * Only the first fragment carries the TCP or UDP header. In a
         * later fragment the bytes at this offset are payload, and reading
         * them as a header would let a crafted fragment pick its own
         * destination port. A knock is one small packet and is never
         * fragmented.
         */
        if (ntohs(iph->frag_off) & IP_OFFMASK) {
            continue;
        }

        l4_offset = ip_offset + ip_hdr_len;

        if (iph->protocol == IPPROTO_TCP) {
            const struct tcphdr *tcph;

            if ((size_t)pkt_len < l4_offset + sizeof(struct tcphdr)) {
                continue;
            }
            tcph = (const struct tcphdr *)(buffer + l4_offset);

            /* A knock is a connection attempt: SYN set, ACK clear. */
            if (tcph->syn != 1 || tcph->ack != 0) {
                continue;
            }
            dport      = ntohs(tcph->dest);
            proto_name = "TCP SYN";
        } else if (iph->protocol == IPPROTO_UDP) {
            const struct udphdr *udph;

            if ((size_t)pkt_len < l4_offset + sizeof(struct udphdr)) {
                continue;
            }
            udph = (const struct udphdr *)(buffer + l4_offset);

            dport      = ntohs(udph->dest);
            proto_name = "UDP";
        } else {
            continue;
        }

        if (!is_knock_port(dport)) {
            continue;
        }

        *src_ip   = iph->saddr;  /* network byte order */
        *dst_port = dport;       /* host byte order    */

        if (LOG_LEVEL >= LEVEL_DEBUG) {
            char ip_str[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &iph->saddr, ip_str, sizeof(ip_str));
            log_debug("%s from %s to port %u", proto_name, ip_str, dport);
        }

        return SNIFFER_OK;
    }
}

void sniffer_close(int sock_fd)
{
    if (sock_fd >= 0) {
        close(sock_fd);
        log_debug("Raw socket closed");
    }
}
