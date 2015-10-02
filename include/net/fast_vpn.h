#ifndef __FAST_VPN_H_
#define __FAST_VPN_H_


#define FAST_VPN_RECV			1
// By default, send through tasklets
#define FAST_VPN_SEND_ASYNC		2
#define FAST_VPN_SEND_SYNC		0


#define FAST_VPN_ACTION_SETUP		1
#define FAST_VPN_ACTION_RELEASE		0

#define FAST_VPN_RES_OK			1
#define FAST_VPN_RES_SKIPPED	0

/* SWNAT section */

#define SWNAT_ORIGIN_RAETH		0x10
#define SWNAT_ORIGIN_RT2860		0x20
#define SWNAT_ORIGIN_USB_MAC	0x30

/* 32-th bit */
#define SWNAT_FNAT_MARK		0x80000000
#define SWNAT_FNAT_MASK		0x7fffffff

/* 31-th bit */
#define SWNAT_PPP_MARK		0x40000000
#define SWNAT_PPP_MASK		0xbfffffff

/* 30-th bit */
#define SWNAT_MC_MARK		0x20000000
#define SWNAT_MC_MASK		0xdfffffff

/* 29-th bit */
#define SWNAT_MC_PROBE_MARK		0x10000000
#define SWNAT_MC_PROBE_MASK		0xefffffff

/* FNAT mark */

#define SWNAT_FNAT_SET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_FNAT_MASK) ^ SWNAT_FNAT_MARK; \
} while (0);

#define SWNAT_FNAT_CHECK_MARK(skb_) \
	(((skb_)->mark & ~SWNAT_FNAT_MASK) == SWNAT_FNAT_MARK)

#define SWNAT_FNAT_RESET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_FNAT_MASK) ^ 0; \
} while (0);

/* End of FNAT mark */

/* PPP mark */

#define SWNAT_PPP_SET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_PPP_MASK) ^ SWNAT_PPP_MARK; \
} while (0);

#define SWNAT_PPP_CHECK_MARK(skb_) \
	(((skb_)->mark & ~SWNAT_PPP_MASK) == SWNAT_PPP_MARK)

#define SWNAT_PPP_RESET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_PPP_MASK) ^ 0; \
} while (0);

/* End of PPP mark */

/* MC mark */

#define SWNAT_MC_SET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_MC_MASK) ^ SWNAT_MC_MARK; \
} while (0);

#define SWNAT_MC_CHECK_MARK(skb_) \
	(((skb_)->mark & ~SWNAT_MC_MASK) == SWNAT_MC_MARK)

#define SWNAT_MC_RESET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_MC_MASK) ^ 0; \
} while (0);

/* End of MC mark */

/* MC probe mark */

#define SWNAT_MC_PROBE_SET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_MC_PROBE_MASK) ^ SWNAT_MC_PROBE_MARK; \
} while (0);

#define SWNAT_MC_PROBE_CHECK_MARK(skb_) \
	(((skb_)->mark & ~SWNAT_MC_PROBE_MASK) == SWNAT_MC_PROBE_MARK)

#define SWNAT_MC_PROBE_RESET_MARK(skb_) \
do { \
	(skb_)->mark = ((skb_)->mark & ~SWNAT_MC_PROBE_MASK) ^ 0; \
} while (0);

/* End of MC probe mark */

#endif //__FAST_VPN_H_
