/*
 * firewall.h — Dynamic iptables rule manager.
 *
 * Opens/closes the protected port for specific client IPs by
 * executing iptables commands. Supports auto-expiry: each opened
 * rule is automatically removed after ACCESS_TIMEOUT seconds.
 */

#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>

/*
 * Open the protected port for a specific client IP.
 * Inserts an iptables ACCEPT rule and spawns a background timer
 * thread that removes the rule after ACCESS_TIMEOUT seconds.
 *
 *   client_ip: Client IP address (network byte order)
 *
 * Returns: 0 on success, -1 on error.
 */
int firewall_open(uint32_t client_ip);

/*
 * Immediately close (revoke) access for a specific client IP.
 * Removes the iptables ACCEPT rule.
 *
 *   client_ip: Client IP address (network byte order)
 *
 * Returns: 0 on success, -1 on error.
 */
int firewall_close(uint32_t client_ip);

/*
 * Remove ALL rules added by this daemon.
 * Called during graceful shutdown to leave the firewall clean.
 */
void firewall_cleanup_all(void);

#endif /* FIREWALL_H */
