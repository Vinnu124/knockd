/*
 * sniffer.h — Raw socket packet sniffer interface.
 *
 * Creates an AF_PACKET raw socket that passively captures TCP SYN
 * packets without binding to any port. Parses Ethernet → IP → TCP
 * headers and reports (source IP, destination port) for each knock.
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>

/*
 * Create and initialize the raw packet socket.
 * Requires root (CAP_NET_RAW).
 *
 * Returns: socket file descriptor on success, -1 on error.
 */
int sniffer_init(void);

/*
 * Block until a TCP SYN packet arrives on one of the configured
 * knock ports (from config.h).
 *
 * On success:
 *   *src_ip   = source IP address (network byte order)
 *   *dst_port = destination port (host byte order)
 *   Returns 0.
 *
 * On error or non-knock packet: returns -1.
 */
int sniffer_next_knock(int sock_fd, uint32_t *src_ip, uint16_t *dst_port);

/*
 * Close the raw socket and release resources.
 */
void sniffer_close(int sock_fd);

#endif /* SNIFFER_H */
