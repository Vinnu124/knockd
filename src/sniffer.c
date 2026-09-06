/*
 * sniffer.c — Raw socket packet sniffer implementation.
 *
 * Creates an AF_PACKET raw socket to passively capture all incoming
 * IP traffic. Parses Ethernet → IP → TCP headers, filters for
 * TCP SYN packets on configured knock ports.
 *
 * Key design:
 *   - Uses ETH_P_IP to only receive IPv4 packets (reduces noise)
 *   - No port binding — completely invisible on the network
 *   - Validates header lengths to avoid buffer over-reads
 */

#include "sniffer.h"
#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>   /* struct tcphdr */
#include <netinet/udp.h>   /* struct udphdr */
#include <arpa/inet.h>

/* Maximum packet buffer size */
#define PKT_BUF_SIZE  65536

/*
 * Check if a port is one of our configured knock ports.
 * Returns 1 if it's a knock port, 0 otherwise.
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

int sniffer_init(void)
{
    /*
     * AF_PACKET + SOCK_RAW: receive raw Ethernet frames.
     * ETH_P_IP: only capture IPv4 packets (skip ARP, IPv6, etc.)
     * Requires CAP_NET_RAW or root.
     */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) {
        log_error("Failed to create raw socket: %s", strerror(errno));
        if (errno == EPERM) {
            log_error("Raw sockets require root privileges. Run with sudo.");
        }
        return -1;
    }

    log_debug("Raw socket created (fd=%d)", sock);
    return sock;
}

int sniffer_next_knock(int sock_fd, uint32_t *src_ip, uint16_t *dst_port)
{
    unsigned char buffer[PKT_BUF_SIZE];

    while (1) {
        /* Block until a packet arrives */
        ssize_t pkt_len = recvfrom(sock_fd, buffer, PKT_BUF_SIZE, 0, NULL, NULL);
        if (pkt_len < 0) {
            if (errno == EINTR) {
                /* Interrupted by signal — let caller handle it */
                return -1;
            }
            log_error("recvfrom() failed: %s", strerror(errno));
            return -1;
        }

        /* ── Layer 2: Ethernet Header ───────────────────────────── */
        if ((size_t)pkt_len < sizeof(struct ethhdr)) {
            continue;  /* Runt frame, skip */
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        /* We requested ETH_P_IP, but double-check */
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue;
        }

        /* ── Layer 3: IP Header ─────────────────────────────────── */
        size_t ip_offset = sizeof(struct ethhdr);
        if ((size_t)pkt_len < ip_offset + sizeof(struct iphdr)) {
            continue;  /* Truncated IP header */
        }

        struct iphdr *iph = (struct iphdr *)(buffer + ip_offset);
        size_t ip_hdr_len = iph->ihl * 4;

        /* ── Layer 4: TCP or UDP Header ─────────────────────────────── */
        uint16_t dport = 0;
        const char *proto_name = "";

        if (iph->protocol == IPPROTO_TCP) {
            size_t tcp_offset = ip_offset + ip_hdr_len;
            if ((size_t)pkt_len < tcp_offset + sizeof(struct tcphdr)) {
                continue;  /* Truncated TCP header */
            }
            struct tcphdr *tcph = (struct tcphdr *)(buffer + tcp_offset);

            /* We ONLY care about SYN packets (SYN=1, ACK=0). */
            if (!(tcph->syn == 1 && tcph->ack == 0)) {
                continue;
            }
            dport = ntohs(tcph->dest);
            proto_name = "TCP SYN";
        } 
        else if (iph->protocol == IPPROTO_UDP) {
            size_t udp_offset = ip_offset + ip_hdr_len;
            if ((size_t)pkt_len < udp_offset + sizeof(struct udphdr)) {
                continue;  /* Truncated UDP header */
            }
            struct udphdr *udph = (struct udphdr *)(buffer + udp_offset);
            
            dport = ntohs(udph->dest);
            proto_name = "UDP";
        }
        else {
            continue; /* Not TCP or UDP */
        }

        /* Check if this is aimed at one of our knock ports */
        if (!is_knock_port(dport)) {
            continue;  /* Not a knock port — ignore */
        }

        /* ── Valid knock detected! ──────────────────────────────── */
        *src_ip   = iph->saddr;   /* Network byte order */
        *dst_port = dport;        /* Host byte order    */

        /* Debug: log the raw knock */
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, ip_str, sizeof(ip_str));
        log_debug("%s captured: %s → port %u", proto_name, ip_str, dport);

        return 0;
    }
}

void sniffer_close(int sock_fd)
{
    if (sock_fd >= 0) {
        close(sock_fd);
        log_debug("Raw socket closed");
    }
}
