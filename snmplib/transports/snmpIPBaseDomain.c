#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/read_config.h>
#include <net-snmp/library/snmp_assert.h>
#include <net-snmp/library/snmpIPBaseDomain.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SETNS
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#endif

static int netsnmp_isnumber(const char *cp)
{
    if (!*cp)
        return 0;

    while (isdigit((unsigned char)*cp))
        cp++;
    return *cp == '\0';
}

/**
 * Parse a Net-SNMP endpoint name.
 * @ep_str: Parsed endpoint name.
 * @endpoint: Endpoint specification in the format
 *   <address>[@<iface>[@<ns>]]:[<port>], <address>[@<iface>[@<ns>]] or <port>.
 *
 * Only overwrite those fields of *@ep_str that have been set in
 * @endpoint. Returns 1 upon success and 0 upon failure.
 */
int netsnmp_parse_ep_str(struct netsnmp_ep_str *ep_str, const char *endpoint)
{
    char *dup, *cp, *addrstr = NULL, *iface = NULL, *ns = NULL, *portstr = NULL;
    unsigned port;

    if (!endpoint)
        return 0;

    dup = strdup(endpoint);
    if (!dup)
        return 0;

    cp = dup;
    if (netsnmp_isnumber(cp)) {
        portstr = cp;
    } else {
        if (*cp == '[') {
            addrstr = cp + 1;
            cp = strchr(cp, ']');
            if (cp) {
                cp[0] = '\0';
                cp++;
            } else {
                goto invalid;
            }
        } else if (*cp != '@' && (*cp != ':' || cp[1] == ':')) {
            addrstr = cp;
            cp = strchr(addrstr, '@');
            if (!cp) {
                cp = strrchr(addrstr, ':');
                if (cp && strchr(dup, ':') < cp)
                    cp = NULL;
            }
        }
        if (cp && *cp == '@') {
            *cp = '\0';
            iface = cp + 1;
            cp = strchr(iface, '@');
            if (!cp)
                cp = strchr(iface, ':');
        }
        if (cp && *cp == '@') {
            *cp = '\0';
            ns = cp + 1;
            cp = strchr(cp + 1, ':');
        }
        if (cp && *cp == ':') {
            *cp++ = '\0';
            portstr = cp;
            if (!netsnmp_isnumber(cp))
                goto invalid;
        } else if (cp && *cp) {
            goto invalid;
        }
    }

    if (addrstr)
        strlcpy(ep_str->addr, addrstr, sizeof(ep_str->addr));
    if (iface)
        strlcpy(ep_str->iface, iface, sizeof(ep_str->iface));
    if (ns) {
	/*
	 * Network namespace names are filenames, meaning they can have
	 * funny characters in them.  If the namespace name starts with
	 * 0x, it is a hex string.
	 */
	size_t len = sizeof(ep_str->ns);
	u_char *p = (u_char *)ep_str->ns;
	read_config_read_octet_string_const(ns, &p, &len);
	netsnmp_assert(p == (u_char *)ep_str->ns);
    }
    if (portstr) {
        port = atoi(portstr);
        if (port >= 0 && port <= 0xffff)
            strlcpy(ep_str->port, portstr, sizeof(ep_str->port));
        else
            goto invalid;
    }

    free(dup);
    return 1;

invalid:
    free(dup);
    return 0;
}

int netsnmp_bindtodevice(int fd, const char *iface)
{
    /* If no interface name has been specified, report success. */
    if (!iface || iface[0] == '\0')
        return 0;

#ifdef HAVE_SO_BINDTODEVICE
    /*
     * +1 to work around the Linux kernel bug that the passed in name is not
     * '\0'-terminated.
     */
    int ifacelen = strlen(iface) + 1;
    int ret;

    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, ifacelen);
    if (ret < 0)
        snmp_log(LOG_ERR, "Binding socket to interface %s failed: %s\n", iface,
                 strerror(errno));
    return ret;
#else
    errno = EINVAL;
    return -1;
#endif
}

/*
 * Open a socket inside a different network namespace.
 * The namespace must already have been created, e.g.,
 * using "ip netns add ___".
 */
int netsnmp_socketat(const char *ns, int domain, int type, int protocol)
{
#ifdef HAVE_SETNS
    int f, newns;
    int s;
    int saved_errno;
    sigset_t set, oset;
    char net_path[255];

    f = open( "/proc/self/ns/net", O_RDONLY );
    if ( f < 0 ) {
        DEBUGMSGTL(("netsnmp_ipbase", "cannot access my own network namespace: %s\n", strerror( errno ) ));
        return -1;
    }
    snprintf(net_path, sizeof(net_path), "%s/%s", "/var/run/netns", ns);
    newns = open( net_path, O_RDONLY );
    if (newns < 0 ) {
        close( f );
        return -1;
    }
    DEBUGMSGTL(("netsnmp_ipbase", "setns to %s\n", net_path));

    /* Block all signals while changing namespace */
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, &oset);

    if (setns( newns, CLONE_NEWNET ) < 0) {
        s = -1;
        saved_errno = errno;
        DEBUGMSGTL(("netsnmp_ipbase", "failed to setns into %s: %s\n",
                 net_path, strerror( errno ) ));
        goto fail;
    }
    s = socket( domain, type, protocol );
    /* We don't explicitly handle errors here, because we have to
     * setns back; we just save the errno.
     */
    if ( s < 0 ) {
        saved_errno = errno;
        DEBUGMSGTL(("netsnmp_ipbase", "failed to open socket inside %s: %s\n",
                 net_path, strerror( errno ) ));
    }
    netsnmp_assert( !( setns( f, CLONE_NEWNET ) < 0 ) );
    /* Failing to set back to our original namespace is fatal. */

fail:
    /* Set signals back now that we're done */
    sigprocmask(SIG_SETMASK, &oset, NULL);
    close( newns );
    close( f );
    if ( s < 0 ) {
        errno = saved_errno;
    }
    return s;
#else
    errno = EINVAL;
    return -1;
#endif
}
