/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2007 MIPS Technologies, Inc.
 * Copyright (C) 2007 Ralf Baechle <ralf@linux-mips.org>
 */
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/smp.h>

#include <asm/smtc_ipi.h>
#include <asm/time.h>
#include <asm/cevt-r4k.h>
#if defined(CONFIG_MIPS_TC3262) || defined(CONFIG_MIPS_TC3162)
#include <asm/tc3162/tc3162.h>
#endif

/*
 * The SMTC Kernel for the 34K, 1004K, et. al. replaces several
 * of these routines with SMTC-specific variants.
 */

#ifndef CONFIG_MIPS_MT_SMTC

static int mips_next_event(unsigned long delta,
                           struct clock_event_device *evt)
{
	unsigned int cnt;
	int res;

	cnt = read_c0_count();
	cnt += delta;
	write_c0_compare(cnt);
	res = ((int)(read_c0_count() - cnt) >= 0) ? -ETIME : 0;

	return res;
}

#endif /* CONFIG_MIPS_MT_SMTC */

void mips_set_clock_mode(enum clock_event_mode mode,
				struct clock_event_device *evt)
{
	/* Nothing to do ...  */
}

DEFINE_PER_CPU(struct clock_event_device, mips_clockevent_device);
int cp0_timer_irq_installed;

#ifndef CONFIG_MIPS_MT_SMTC

#if defined(CONFIG_RALINK_SYSTICK) && defined(CONFIG_RALINK_MT7621)
void ra_percpu_event_handler(void)
{
	struct clock_event_device *cd;
	int cpu = smp_processor_id();

	cd = &per_cpu(mips_clockevent_device, cpu);
	cd->event_handler(cd);
}
#endif

irqreturn_t c0_compare_interrupt(int irq, void *dev_id)
{
	const int r2 = cpu_has_mips_r2;
	struct clock_event_device *cd;
	int cpu = smp_processor_id();
#if defined(CONFIG_MIPS_TC3262) || defined(CONFIG_MIPS_TC3162)
	unsigned int tmp;
#endif
	/*
	 * Suckage alert:
	 * Before R2 of the architecture there was no way to see if a
	 * performance counter interrupt was pending, so we have to run
	 * the performance counter interrupt handler anyway.
	 */
	if (handle_perf_irq(r2))
		goto out;

#if defined(CONFIG_MIPS_TC3262) || defined(CONFIG_MIPS_TC3162)
	if (isRT63165 || isRT63365 || isMT751020) {
		if (cpu == 0) {
			mips_timer_ack();
		} else {
			tmp = regRead32(CR_CPUTMR_CNT1) + (mips_hpt_frequency/HZ);
			regWrite32(CR_CPUTMR_CMR1, tmp);
		}
	}
#endif

	/*
	 * The same applies to performance counter interrupts.  But with the
	 * above we now know that the reason we got here must be a timer
	 * interrupt.  Being the paranoiacs we are we check anyway.
	 */

	if (!r2 || (read_c0_cause() & (1 << 30))) {
		/* Clear Count/Compare Interrupt */
		write_c0_compare(read_c0_compare());
		cd = &per_cpu(mips_clockevent_device, cpu);
		cd->event_handler(cd);
	}
out:
	return IRQ_HANDLED;
}

#endif /* Not CONFIG_MIPS_MT_SMTC */

struct irqaction c0_compare_irqaction = {
	.handler = c0_compare_interrupt,
	.flags = IRQF_DISABLED | IRQF_PERCPU | IRQF_TIMER,
	.name = "timer",
};


void mips_event_handler(struct clock_event_device *dev)
{
}

/*
 * FIXME: This doesn't hold for the relocated E9000 compare interrupt.
 */
static int c0_compare_int_pending(void)
{
	return (read_c0_cause() >> cp0_compare_irq_shift) & (1ul << CAUSEB_IP);
}

/*
 * Compare interrupt can be routed and latched outside the core,
 * so a single execution hazard barrier may not be enough to give
 * it time to clear as seen in the Cause register.  4 time the
 * pipeline depth seems reasonably conservative, and empirically
 * works better in configurations with high CPU/bus clock ratios.
 */

#define compare_change_hazard() \
	do { \
		irq_disable_hazard(); \
		irq_disable_hazard(); \
		irq_disable_hazard(); \
		irq_disable_hazard(); \
	} while (0)

int c0_compare_int_usable(void)
{
	unsigned int delta;
	unsigned int cnt;

	/*
	 * IP7 already pending?  Try to clear it by acking the timer.
	 */
	if (c0_compare_int_pending()) {
		write_c0_compare(read_c0_count());
		compare_change_hazard();
		if (c0_compare_int_pending())
			return 0;
	}

	for (delta = 0x10; delta <= 0x400000; delta <<= 1) {
		cnt = read_c0_count();
		cnt += delta;
		write_c0_compare(cnt);
		compare_change_hazard();
		if ((int)(read_c0_count() - cnt) < 0)
		    break;
		/* increase delta if the timer was already expired */
	}

	while ((int)(read_c0_count() - cnt) <= 0)
		;	/* Wait for expiry  */

	compare_change_hazard();
	if (!c0_compare_int_pending())
		return 0;

	write_c0_compare(read_c0_count());
	compare_change_hazard();
	if (c0_compare_int_pending())
		return 0;

	/*
	 * Feels like a real count / compare timer.
	 */
	return 1;
}

#ifndef CONFIG_MIPS_MT_SMTC

#if defined(CONFIG_RALINK_SYSTICK) && defined(CONFIG_RALINK_MT7621)
extern void ra_systick_event_broadcast(const struct cpumask *mask);
#endif

int __cpuinit r4k_clockevent_init(void)
{
	unsigned int cpu = smp_processor_id();
	struct clock_event_device *cd;
	unsigned int irq;

	if (!cpu_has_counter || !mips_hpt_frequency)
		return -ENXIO;

	if (!c0_compare_int_usable())
		return -ENXIO;

	/*
	 * With vectored interrupts things are getting platform specific.
	 * get_c0_compare_int is a hook to allow a platform to return the
	 * interrupt number of it's liking.
	 */
	irq = MIPS_CPU_IRQ_BASE + cp0_compare_irq;
	if (get_c0_compare_int)
		irq = get_c0_compare_int();

	cd = &per_cpu(mips_clockevent_device, cpu);

	cd->features		= CLOCK_EVT_FEAT_ONESHOT;

#if defined(CONFIG_RALINK_SYSTICK) && defined(CONFIG_RALINK_MT7621)
	cd->features		= cd->features | CLOCK_EVT_FEAT_DUMMY;
	cd->broadcast		= ra_systick_event_broadcast;
#endif

	/* Calculate the min / max delta */
	cd->name		= "MIPS";
#if defined (CONFIG_RALINK_SOC) || defined (CONFIG_MIPS_TC3262)
	clockevent_set_clock(cd, mips_hpt_frequency);
#endif
	cd->max_delta_ns	= clockevent_delta2ns(0x7fffffff, cd);
	cd->min_delta_ns	= clockevent_delta2ns(0x300, cd);
	cd->rating		= 300;
	cd->irq			= irq;
	cd->cpumask		= cpumask_of(cpu);
	cd->set_next_event	= mips_next_event;
	cd->set_mode		= mips_set_clock_mode;
	cd->event_handler	= mips_event_handler;


	clockevents_register_device(cd);

	if (cp0_timer_irq_installed)
		return 0;

	cp0_timer_irq_installed = 1;

	setup_irq(irq, &c0_compare_irqaction);

	return 0;
}

#endif /* Not CONFIG_MIPS_MT_SMTC */
