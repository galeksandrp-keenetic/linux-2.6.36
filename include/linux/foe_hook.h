#ifndef __FOE_HOOK_H
#define __FOE_HOOK_H

#define FOE_MAGIC_PCI		    0x7273
#define FOE_MAGIC_WLAN		    0x7274
#define FOE_MAGIC_GE		    0x7275
#define FOE_MAGIC_PPE		    0x7276
#define FOE_MAGIC_ATM		    0x7277

#ifdef CONFIG_TCSUPPORT_MT7510_FE
#define FOE_MAGIC_PTM		    0x7278
#define FOE_MAGIC_EPON		    0x7279
#define FOE_MAGIC_GPON		    0x727a
//#define FOE_MAGIC_CRYPTO	    0x727b

#define FOE_MAGIC_CRYPTO_E_1	    0x727b
#define FOE_MAGIC_CRYPTO_D_1	    0x727c
#define FOE_MAGIC_CRYPTO_E_2	    0x727d
#define FOE_MAGIC_CRYPTO_D_2	    0x727e
#define FOE_MAGIC_OFFLOAD	    0x727f
#endif

#define HWNAT_IPSEC_LEARING 0
#define HWNAT_IPSEC_SPEED 1
#define HWNAT_IPSEC_ROLLBACK 2

#define IPSEC_SKB_CB			47

#define FOE_OPE_GETENTRYNUM 0
#define FOE_OPE_CLEARENTRY  1


#ifdef CONFIG_TCSUPPORT_MT7510_FE
struct qdma_atm{
	unsigned long int txq:4;
	unsigned long int pppoa:1;//sw self use
	unsigned long int ipoa:1;//sw self use
	unsigned long int resv0:12;
	unsigned long int xoa:1;
	unsigned long int uu:8;
	unsigned long int clp:1;
	unsigned long int vcnum:4;
};

struct qdma_ptm{
	unsigned long int txq:4;
	unsigned long int resv0:6;
	unsigned long int tsid:5;
	unsigned long int tse:1;
	unsigned long int resv1:12;
	unsigned long int channel:4;
};

struct qdma_epon{
	unsigned long int txq:4;
	unsigned long int resv0:6;
	unsigned long int tsid:5;
	unsigned long int tse:1;
	unsigned long int resv1:12;
	unsigned long int llid:4;
};

struct qdma_gpon{
	unsigned long int txq:4;
	unsigned long int resv0:6;
	unsigned long int tsid:5;
	unsigned long int tse:1;
	unsigned long int gemid:12;
	unsigned long int tcon:4;
};

struct pdma{
	unsigned long int txq:4;
	unsigned long int resv0:27;
	unsigned long int is_wan:1;//sw self use
};
struct port_info {
	union {
		struct qdma_atm qatm;	
		struct qdma_ptm qptm;
		struct qdma_epon qepon;
		struct qdma_gpon qgpon;
		struct pdma pdma_eth;
		unsigned long int word;
	};
};
#endif

struct psepkt_stats {
	unsigned long	rx_pkts;		/* total packets received	*/
	unsigned long	tx_pkts;		/* total packets transmitted	*/
};

#include <linux/skbuff.h>

extern int (*ra_sw_nat_hook_rx) (struct sk_buff * skb);
#ifdef CONFIG_TCSUPPORT_MT7510_FE
extern int (*ra_sw_nat_hook_tx) (struct sk_buff * skb, struct port_info * pinfo, int magic);
#else
extern int (*ra_sw_nat_hook_tx) (struct sk_buff * skb, int gmac_no);
#endif
extern int (*ra_sw_nat_hook_free) (struct sk_buff * skb);
extern int (*ra_sw_nat_hook_rxinfo) (struct sk_buff * skb, int magic, char *data, int data_length);
extern int (*ra_sw_nat_hook_txq) (struct sk_buff * skb, int txq);
extern int (*ra_sw_nat_hook_magic) (struct sk_buff * skb, int magic);
extern int (*ra_sw_nat_hook_set_magic) (struct sk_buff * skb, int magic);
extern int (*ra_sw_nat_hook_xfer) (struct sk_buff *skb, const struct sk_buff *prev_p);
extern int (*ra_sw_nat_hook_foeentry) (void * inputvalue,int operation);

#ifdef CONFIG_TCSUPPORT_RA_HWNAT_ENHANCE_HOOK
extern int (*ra_sw_nat_hook_drop_packet) (struct sk_buff * skb);
extern int (*ra_sw_nat_hook_clean_table) (void);
#endif
extern void (*ra_sw_nat_hook_pse_stats) (struct psepkt_stats* pf,int port);
extern void (*ra_sw_nat_hook_release_dstport) (uint32_t port);
extern void (*ra_sw_nat_hook_acquire_dstport) (uint32_t port, char *name);
extern int (*ra_sw_nat_hook_get_stats) (struct net_device *dev, struct rtnl_link_stats64 *out_stats);
#endif
