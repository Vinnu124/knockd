/*
 * firewall.h — iptables rule manager with time-limited grants.
 *
 * Every rule knockd adds goes into its own chain (KNOCKD_CHAIN), which the
 * daemon creates at startup and jumps INPUT into. Rules the operator wrote
 * — in particular the default DROP that makes port knocking worth anything
 * — are never touched.
 */

#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>

/*
 * Create and hook up knockd's chain, and allocate the grant table.
 *
 * Any rules left in the chain by a previous run are flushed, so a daemon
 * that was killed does not leave stale access behind.
 *
 * Returns 0 on success, -1 if the firewall could not be set up (the daemon
 * should not start in that case — it would accept knocks and silently fail
 * to act on them).
 */
int firewall_init(void);

/*
 * Grant client_ip access to the protected port for ACCESS_TIMEOUT seconds.
 * An address that already has access has its deadline extended instead of
 * getting a second, identical rule.
 *
 *   client_ip: network byte order
 *
 * Returns 0 on success, -1 on error.
 */
int firewall_open(uint32_t client_ip);

/*
 * Revoke access for client_ip immediately.
 *
 * Returns 0 on success, -1 on error.
 */
int firewall_close(uint32_t client_ip);

/*
 * Close any grant whose deadline has passed.
 *
 * Expiry is driven from here rather than from a timer thread per grant, so
 * a flood of completed sequences cannot spawn unbounded threads and
 * shutdown never races with one still sleeping. Call it regularly — once
 * per processor loop iteration is what the daemon does.
 */
void firewall_tick(void);

/*
 * Remove everything knockd added: the grants, the chain, and the jump into
 * it if knockd was the one that added that. Call once at shutdown.
 */
void firewall_shutdown(void);

#endif /* FIREWALL_H */
