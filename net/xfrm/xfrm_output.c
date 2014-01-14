/*
 * xfrm_output.c - Common IPsec encapsulation code.
 *
 * Copyright (c) 2007 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/xfrm.h>
#ifdef CONFIG_TCSUPPORT_RA_HWNAT
#include <linux/foe_hook.h>
#endif
#if  defined(CONFIG_RA_HW_NAT) || defined(CONFIG_RA_HW_NAT_MODULE)
#include "../nat/hw_nat/ra_nat.h"
#endif
#ifdef CONFIG_TCSUPPORT_IPSEC_PASSTHROUGH
#include <net/mtk_esp.h>
#endif

static int xfrm_output2(struct sk_buff *skb);

static int xfrm_state_check_space(struct xfrm_state *x, struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	int nhead = dst->header_len + LL_RESERVED_SPACE(dst->dev)
		- skb_headroom(skb);
	int ntail = dst->dev->needed_tailroom - skb_tailroom(skb);

	if (nhead <= 0) {
		if (ntail <= 0)
			return 0;
		nhead = 0;
	} else if (ntail < 0)
		ntail = 0;

	return pskb_expand_head(skb, nhead, ntail, GFP_ATOMIC);
}

static int xfrm_output_one(struct sk_buff *skb, int err)
{
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;
	struct net *net = xs_net(x);

	if (err <= 0)
		goto resume;
#ifdef CONFIG_TCSUPPORT_IPSEC_PASSTHROUGH
		if(VPN_PASSTHROUGH_SWITCH_ON == gpVpnPTPara->vpnpassthroughswitch)
		{
			struct ipsec_para_s ipsec_data;
			ipsec_data.flag = HWNAT_IPSEC_LEARING;
			ipsec_data.data.learn.skb = skb;
			ipsec_data.data.learn.x = x;
			err = ipsec_esp_output_pt(&ipsec_data);
			if (err)
				goto error_nolock;
		}
#endif

	do {
		err = xfrm_state_check_space(x, skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			goto error_nolock;
		}

		err = x->outer_mode->output(x, skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEMODEERROR);
			goto error_nolock;
		}

		spin_lock_bh(&x->lock);
		err = xfrm_state_check_expire(x);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEEXPIRED);
			goto error;
		}

		if (x->type->flags & XFRM_TYPE_REPLAY_PROT) {
			XFRM_SKB_CB(skb)->seq.output = ++x->replay.oseq;
			if (unlikely(x->replay.oseq == 0)) {
				XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATESEQERROR);
				x->replay.oseq--;
				xfrm_audit_state_replay_overflow(x, skb);
				err = -EOVERFLOW;
				goto error;
			}
			if (xfrm_aevent_is_on(net))
				xfrm_replay_notify(x, XFRM_REPLAY_UPDATE);
		}

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock_bh(&x->lock);
#if 0//def CONFIG_TCSUPPORT_RA_HWNAT
/* Don't let HWNAT has the change to learn ipsec packets!
 * Once HWNAT learned ipsec packets, it will forward packets
 * directly from Rx to Tx, which will cause ipsec packets
 * not being decrypted.
 */
    if (ra_sw_nat_hook_free)
        ra_sw_nat_hook_free(skb);
#endif
#if defined(CONFIG_RA_HW_NAT) || defined(CONFIG_RA_HW_NAT_MODULE)
		if( IS_SPACE_AVAILABLED(skb)  &&
			((FOE_MAGIC_TAG(skb) == FOE_MAGIC_PCI) ||
			(FOE_MAGIC_TAG(skb) == FOE_MAGIC_WLAN) ||
			(FOE_MAGIC_TAG(skb) == FOE_MAGIC_GE))){
			FOE_ALG(skb)=1;
		}
#endif
		err = x->type->output(x, skb);
#if defined(CONFIG_MTK_CRYPTO_DRIVER) || defined(CONFIG_RALINK_HWCRYPTO) || defined(CONFIG_RALINK_HWCRYPTO_MODULE)
		if (skb->protocol == htons(ETH_P_IP))
		{
			if (err == 1)
				return err;
		}
#endif	
		if (err == -EINPROGRESS)
			goto out_exit;

resume:
#if defined(CONFIG_MTK_CRYPTO_DRIVER) || defined(CONFIG_RALINK_HWCRYPTO) || defined(CONFIG_RALINK_HWCRYPTO_MODULE)
		if (skb->protocol == htons(ETH_P_IPV6))
#else	
		{	
			if (err) {
				XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEPROTOERROR);
				goto error_nolock;
			}
		}
#endif
		dst = skb_dst_pop(skb);
		if (!dst) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			err = -EHOSTUNREACH;
			goto error_nolock;
		}
		skb_dst_set(skb, dst_clone(dst));
		x = dst->xfrm;
		if(x && err == 0){
			printk("do not support double encryption now!\n");
 			break; 
		}
	} while (x && !(x->outer_mode->flags & XFRM_MODE_FLAG_TUNNEL));

	err = 0;

out_exit:
	return err;
error:
	spin_unlock_bh(&x->lock);
error_nolock:
	kfree_skb(skb);
	goto out_exit;
}

int xfrm_output_resume(struct sk_buff *skb, int err)
{
	while (likely((err = xfrm_output_one(skb, err)) == 0)) {
		nf_reset(skb);

		err = skb_dst(skb)->ops->local_out(skb);
		if (unlikely(err != 1))
			goto out;

		if (!skb_dst(skb)->xfrm)
			return dst_output(skb);

		err = nf_hook(skb_dst(skb)->ops->family,
			      NF_INET_POST_ROUTING, skb,
			      NULL, skb_dst(skb)->dev, xfrm_output2);
		if (unlikely(err != 1))
			goto out;
	}

	if (err == -EINPROGRESS)
		err = 0;

#if defined(CONFIG_MTK_CRYPTO_DRIVER) || defined(CONFIG_RALINK_HWCRYPTO) || defined(CONFIG_RALINK_HWCRYPTO_MODULE)
	if (skb->protocol = htons(ETH_P_IP))
		return 0;
#endif
out:
	return err;
}
EXPORT_SYMBOL_GPL(xfrm_output_resume);

static int xfrm_output2(struct sk_buff *skb)
{
	return xfrm_output_resume(skb, 1);
}

static int xfrm_output_gso(struct sk_buff *skb)
{
	struct sk_buff *segs;

	segs = skb_gso_segment(skb, 0);
	kfree_skb(skb);
	if (IS_ERR(segs))
		return PTR_ERR(segs);

	do {
		struct sk_buff *nskb = segs->next;
		int err;

		segs->next = NULL;
		err = xfrm_output2(segs);

		if (unlikely(err)) {
			while ((segs = nskb)) {
				nskb = segs->next;
				segs->next = NULL;
				kfree_skb(segs);
			}
			return err;
		}

		segs = nskb;
	} while (segs);

	return 0;
}

int xfrm_output(struct sk_buff *skb)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	int err;

	if (skb_is_gso(skb))
		return xfrm_output_gso(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		err = skb_checksum_help(skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			kfree_skb(skb);
			return err;
		}
	}

	return xfrm_output2(skb);
}

int xfrm_inner_extract_output(struct xfrm_state *x, struct sk_buff *skb)
{
	struct xfrm_mode *inner_mode;
	if (x->sel.family == AF_UNSPEC)
		inner_mode = xfrm_ip2inner_mode(x,
				xfrm_af2proto(skb_dst(skb)->ops->family));
	else
		inner_mode = x->inner_mode;

	if (inner_mode == NULL)
		return -EAFNOSUPPORT;
	return inner_mode->afinfo->extract_output(x, skb);
}

EXPORT_SYMBOL_GPL(xfrm_output);
EXPORT_SYMBOL_GPL(xfrm_inner_extract_output);
