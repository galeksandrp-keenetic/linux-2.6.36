#ifndef _LINUX_NTC_SHAPER_HOOKS_H
#define _LINUX_NTC_SHAPER_HOOKS_H

#include <linux/spinlock.h>

struct sk_buff;

typedef unsigned int ntc_shaper_hook_fn(struct sk_buff *skb,
										int (*okfn)(struct sk_buff *));

extern rwlock_t ntc_shaper_lock;
extern ntc_shaper_hook_fn *ntc_shaper_ingress_hook;
extern ntc_shaper_hook_fn *ntc_shaper_egress_hook;

static inline ntc_shaper_hook_fn *
ntc_shaper_ingress_hook_get(void)
{
	read_lock_bh(&ntc_shaper_lock);

	return ntc_shaper_ingress_hook;
}

static inline void
ntc_shaper_ingress_hook_put(void)
{
	read_unlock_bh(&ntc_shaper_lock);
}

static inline ntc_shaper_hook_fn *
ntc_shaper_egress_hook_get(void)
{
	read_lock_bh(&ntc_shaper_lock);

	return ntc_shaper_egress_hook;
}

static inline void
ntc_shaper_egress_hook_put(void)
{
	read_unlock_bh(&ntc_shaper_lock);
}

static inline void
ntc_shaper_hooks_set(ntc_shaper_hook_fn *ingress_hook,
					 ntc_shaper_hook_fn *egress_hook)
{
	write_lock_bh(&ntc_shaper_lock);
	ntc_shaper_ingress_hook = ingress_hook;
	ntc_shaper_egress_hook = egress_hook;
	write_unlock_bh(&ntc_shaper_lock);
}

#endif

