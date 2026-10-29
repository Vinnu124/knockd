/*
 * sniffer.h — Raw packet capture.
 *
 * Captures incoming TCP SYN and UDP packets from an AF_PACKET socket and
 * reports the ones aimed at a configured knock port. Nothing is bound and
 * nothing is sent, so the daemon adds no listening socket a scan could
 * find.
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>

/* sniffer_next_knock() return values. */
#define SNIFFER_OK     0    /* a knock was captured                        */
#define SNIFFER_AGAIN  (-1) /* nothing to report yet — call again          */
#define SNIFFER_ERROR  (-2) /* the socket failed — stop capturing          */

/*
 * Create the capture socket. Requires CAP_NET_RAW (so, root).
 *
 * Honours KNOCK_INTERFACE: when set, packets from other interfaces are
 * ignored and an unknown name is a startup error.
 *
 * Returns the socket descriptor, or -1 on error.
 */
int sniffer_init(void);

/*
 * Wait for the next packet aimed at a knock port.
 *
 * On SNIFFER_OK:
 *   *src_ip   = source IP, network byte order
 *   *dst_port = destination port, host byte order
 *
 * The call returns SNIFFER_AGAIN every few hundred milliseconds even when
 * no packet arrives, so the caller gets a chance to notice that the daemon
 * is stopping. Callers must therefore treat SNIFFER_AGAIN as "nothing
 * happened", not as a failure.
 */
int sniffer_next_knock(int sock_fd, uint32_t *src_ip, uint16_t *dst_port);

/*
 * Close the capture socket.
 */
void sniffer_close(int sock_fd);

#endif /* SNIFFER_H */
