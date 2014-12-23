#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#else
#include <linux/config.h>
#endif

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/delay.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <net/arp.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/proc_fs.h>

extern int (*vpn_pthrough)(struct sk_buff *skb, int in);
extern int (*vpn_pthrough_setup)(uint32_t sip, int add);
extern int (*l2tp_input)(struct sk_buff *skb);

#define HWADDR_LEN					6
#define MAX_VPN_TABLE				32

typedef struct __st_hdr {
	struct net_device *dev;
	uint32_t sip;
	uint8_t smac[HWADDR_LEN];
	uint8_t dmac[HWADDR_LEN];
	struct vlan_ethhdr vh;
	int vset;
} VPN_HDR_TABLE, *PVPN_HDR_TABLE;

static VPN_HDR_TABLE vpn_hdr_tbl[MAX_VPN_TABLE];
static int vpn_tbl_cnt = 0;
static int vpn_tbl_ovr = 0;
static struct tasklet_struct vpn_tx_task;
static struct sk_buff_head vpn_tx_q;

#define SEND_PER_LOCK	16

PVPN_HDR_TABLE vpn_find_hdr(uint32_t sip) {
	int ipos;
	for( ipos = 0; ipos < vpn_tbl_cnt; ipos++ )
		if( vpn_hdr_tbl[ipos].sip == sip ) return &vpn_hdr_tbl[ipos];
	return NULL;
}

void vpn_add_hdr(struct net_device *dev, 	uint32_t sip, 	uint8_t *smac, uint8_t *dmac, struct vlan_ethhdr *veth) {
	int ipos;
	PVPN_HDR_TABLE phdr = vpn_find_hdr(sip);
	
	if( !phdr ) {
		if( vpn_tbl_cnt < MAX_VPN_TABLE ) phdr = &vpn_hdr_tbl[vpn_tbl_cnt++];
		else {
			phdr = &vpn_hdr_tbl[vpn_tbl_ovr++];
			vpn_tbl_ovr %= MAX_VPN_TABLE;
		}
	}
	
	phdr->dev = dev;
	phdr->sip = sip;
	if( smac ) memcpy(phdr->smac, smac, HWADDR_LEN);
	if( dmac ) memcpy(phdr->dmac, dmac, HWADDR_LEN);
	if( veth ) {
		memcpy(&phdr->vh, veth, VLAN_ETH_HLEN);
		phdr->vset = 1;
		
		/* need to switch smac/dmac in vlan header */
		for( ipos = 0; ipos < ETH_ALEN; ipos++ ) {
			phdr->vh.h_dest[ipos] ^= phdr->vh.h_source[ipos];
			phdr->vh.h_source[ipos] ^= phdr->vh.h_dest[ipos];
			phdr->vh.h_dest[ipos] ^= phdr->vh.h_source[ipos];
		}
		
	} else phdr->vset = 0;
}

void vpn_rem_hdr(uint32_t sip) {
	PVPN_HDR_TABLE phdr = vpn_find_hdr(sip);
	
	if( phdr ) {
		if( vpn_tbl_cnt > 1 ) {
			if( phdr != &vpn_hdr_tbl[vpn_tbl_cnt - 1] ) memmove(phdr, &vpn_hdr_tbl[vpn_tbl_cnt - 1], sizeof(VPN_HDR_TABLE));
			vpn_tbl_cnt--;
			vpn_tbl_ovr = 0;
		} else {
			vpn_tbl_cnt = 0;
			vpn_tbl_ovr = 0;
		}
	}
}

void vpn_clr_hdr(uint32_t sip) {
	PVPN_HDR_TABLE phdr = vpn_find_hdr(sip);
	
	if( phdr ) 
		phdr->dev = NULL;
}

void vpn_hard_tx(unsigned long u) {
	struct sk_buff *skb[SEND_PER_LOCK];
	unsigned long flags;
	int icnt, ipos;
 	
	while( 1 ) {
		spin_lock_irqsave(&vpn_tx_q.lock, flags);
		for( icnt = 0; icnt < SEND_PER_LOCK; icnt++ ) {
			if( !(skb[icnt] = __skb_dequeue(&vpn_tx_q)) ) break;
		}
		spin_unlock_irqrestore(&vpn_tx_q.lock, flags);
		if( !icnt ) break;
		
		for( ipos = 0; ipos < icnt; ipos++ )
			dev_queue_xmit(skb[ipos]);
	}
}

int vpn_cross(struct sk_buff *skb, int in) {
	unsigned char *smac, *dmac;
	struct iphdr *iph;
	struct udphdr *udp;
	struct vlan_ethhdr *veth;
	uint32_t saddr, daddr;
	PVPN_HDR_TABLE phdr;
	__be16 vskbp;
	int imod;
	
	int (*l2tp_rx)(struct sk_buff *skb);
	
	if( !vpn_tbl_cnt ) return 0; /* fast skip pkt */
	
	if( in == 1 ) {
		if( eth_hdr(skb)->h_proto == htons(ETH_P_8021Q) ) {
			veth = (struct vlan_ethhdr *)(skb_mac_header(skb));
		} else veth = NULL;
	
	 	if( skb->dev && (eth_hdr(skb)->h_proto == htons(ETH_P_IP) || (veth && veth->h_vlan_encapsulated_proto == htons(ETH_P_IP))) ) {
	 		if( veth ) iph = (struct iphdr *)(skb_mac_header(skb) + VLAN_ETH_HLEN);
	 		else iph = (struct iphdr *)(skb_mac_header(skb) + ETH_HLEN);
	 			
	 		if( (iph->frag_off & htons(IP_MF | IP_OFFSET)) || !(phdr = vpn_find_hdr(iph->saddr)) )
	 			return 0; /* frag or unknown source */
	 		
	 		dmac = skb_mac_header(skb);
 			smac = dmac + HWADDR_LEN;
	 		saddr = iph->saddr;
	 		
	 		if( !phdr->dev ) 
	 			vpn_add_hdr(skb->dev, saddr, smac, dmac, veth);
	 			
			if( iph->protocol == IPPROTO_UDP &&
				 (udp = (struct udphdr*)((char *)iph + (iph->ihl << 2))) &&
				 udp->dest == htons(1701) && 
				 udp->source == htons(1701) &&
				 (l2tp_rx = rcu_dereference(l2tp_input)) ) {
				 
				 if( veth ) {
	 				skb_pull(skb, VLAN_HLEN);
					skb_reset_network_header(skb);
				
					if( skb->pkt_type == PACKET_OTHERHOST ) {
						skb->pkt_type = PACKET_HOST;
						imod = 1;	
					} else imod = 0;
					
					vskbp = skb->protocol;
					skb->protocol = htons(ETH_P_IP);
	 			 }
				 
				 if( l2tp_rx(skb) == 1 ) return 1;
				 
				 /* remod src packet */
				 if( veth ) {
					 skb_push(skb, VLAN_HLEN);
					 skb_reset_network_header(skb);
					 if( imod ) skb->pkt_type = PACKET_OTHERHOST;
					 skb->protocol = vskbp;
				 }
			}
		}
	} else {
		if( (iph = ip_hdr(skb)) ) {
			daddr = iph->daddr;
	 		
	 		if( !(phdr = vpn_find_hdr(daddr)) || !phdr->dev ) 
	 			return 0;
	 			
	 		skb->dev = phdr->dev;
	 		
	 		if( !phdr->vset ) dmac = (uint8_t *)skb_push(skb, ETH_HLEN);
	 		else dmac = (uint8_t *)skb_push(skb, VLAN_ETH_HLEN);
	 		
 			skb_reset_mac_header(skb);
 			
 			if( !phdr->vset ) {
 				memcpy(dmac, phdr->smac, HWADDR_LEN);
 				dmac += HWADDR_LEN;
 				memcpy(dmac, phdr->dmac, HWADDR_LEN);
 				dmac += HWADDR_LEN;
 			
 				*dmac++ = 0x08;
 				*dmac++ = 0x00;
 			} else {
 				memcpy(dmac, &phdr->vh, VLAN_ETH_HLEN);
 			}
 			
 			if( in == 0 ) dev_queue_xmit(skb);
 			else {
 				skb_queue_tail(&vpn_tx_q, skb);
				tasklet_schedule(&vpn_tx_task);
 			}
 			
 			return 1;
		}
	}

	return 0;
}

int vpn_setup(uint32_t sip, int add) {
	if( !sip || sip == 0xffffffff ) return -1;

	printk("Fast VPN ctrl: %08x, %d\n", sip, add);

	if( add ) vpn_add_hdr(NULL, sip, NULL, NULL, NULL);
	else vpn_rem_hdr(sip);
	
	return 0;
}

static int __init fast_vpn_init(void) {	
	skb_queue_head_init(&vpn_tx_q);
	tasklet_init(&vpn_tx_task, vpn_hard_tx, 0);

	rcu_assign_pointer(vpn_pthrough, vpn_cross);
	rcu_assign_pointer(vpn_pthrough_setup, vpn_setup);
	
	printk("Fast VPN init, v1.01\n");
	return 0;
}

static void __exit fast_vpn_fini(void) {
	rcu_assign_pointer(vpn_pthrough, NULL);
	rcu_assign_pointer(vpn_pthrough_setup, NULL);

	tasklet_kill(&vpn_tx_task);
	skb_queue_purge(&vpn_tx_q);
	printk("Fast VPN unload\n");
}

module_init(fast_vpn_init);
module_exit(fast_vpn_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("http://www.ndmsystems.com");
