#ifndef _SNMPIPBASEDOMAIN_H_
#define _SNMPIPBASEDOMAIN_H_

#include <net-snmp/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/**
 * SNMP endpoint specification.
 * @param a     Address family, network address and port number.
 * @param iface Network interface name in ASCII format. May be empty.
 * @param ns    Network namespace for this address. May be empty.
 */
struct netsnmp_ep {
    union {
        struct sockaddr_in  sin;
#if defined(NETSNMP_TRANSPORT_UDPIPV6_DOMAIN) || \
    defined(NETSNMP_TRANSPORT_TCPIPV6_DOMAIN)
        struct sockaddr_in6 sin6;
#endif
    } a;
    char iface[16];
    char ns[16];
};

/**
 * SNMP endpoint with the network name in ASCII format.
 * @param addr Network address or host name as an ASCII string.
 * @param iface Network interface, e.g. "lo".
 * @param ns    Network namespace for this address. May be empty.
 * @param port Port number. "" means that no port number has been specified. "0"
 *   means "bind to any port".
 */
struct netsnmp_ep_str {
    char     addr[64];
    char     iface[16];
    char     ns[16];
    char     port[6];
};

int netsnmp_parse_ep_str(struct netsnmp_ep_str *ep_str, const char *endpoint);
int netsnmp_bindtodevice(int fd, const char *iface);
int netsnmp_socketat(const char *ns, int domain, int type, int protocol);

#endif /* _SNMPIPBASEDOMAIN_H_ */
