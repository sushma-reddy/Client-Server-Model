#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/icmp.h>

struct iphdr *ip_header;            //ip header struct
char src_ip[16];                                        // Packet source IP
char dest_ip[16];                                       // Packet Destination IP
//List of IP's to block
char array[3][20] = {"216.151.163.132","64.90.41.204","192.168.2.3"};
int size=3;
static struct nf_hook_ops netfilter_ops_out; /* NF_IP_POST_ROUTING */

unsigned int main_hook(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff*))
{
   int i=0;
   ip_header = (struct iphdr *)skb_network_header(skb);
   snprintf(src_ip,16,"%pI4",&ip_header->saddr);              //Storing IP address of the source in the form of x.x.x.x
   snprintf(dest_ip,16,"%pI4",&ip_header->daddr);             //Storing IP address of the destination in the form of x.x.x.x
   if (ip_header->protocol == 6) {
      for(i=0;i<size;i++){
        if (strcmp(array[i],dest_ip)==0)
           break;
      }
      if (i!=size){
        printk(KERN_INFO "Dropped:http request does not have valid dst address:%s\n",dest_ip);
        return NF_DROP;
      }
      else {
        printk(KERN_INFO "Accepted:http request have valid dst address:%s\n",dest_ip);
        return NF_ACCEPT;
     }
   }
   return NF_ACCEPT;
}


int init_module()
{
        netfilter_ops_out.hook                  =       main_hook;
        netfilter_ops_out.pf                    =       PF_INET;
        netfilter_ops_out.hooknum               =       NF_INET_POST_ROUTING;
        netfilter_ops_out.priority              =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops_out); /* register NF_IP_POST_ROUTING hook */
        printk(KERN_INFO "adding firewall module\n");
        return 0;
}

void cleanup_module()
{
        nf_unregister_hook(&netfilter_ops_out); /*unregister NF_IP_POST_ROUTING hook*/
        printk(KERN_INFO "removing firewall module\n");
}
