/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#ifndef VMI_H
#define VMI_H

#include <rec.h>
#include <smc-rmi.h>

#ifndef VMI_PERF_MEASURE
#define VMI_PERF_MEASURE	1
#endif

#ifdef CONFIG_RMM_VMI
bool vmi_handle(struct rec *rec, struct rmi_rec_run *rec_run);

extern bool vmi_trap_enabled;
extern unsigned long vmi_trap_ipa;
extern unsigned long vmi_trap_pa;
extern unsigned long vmi_last_cycles;
extern unsigned long vmi_total_cycles;
extern unsigned long vmi_cnt_freq;
extern unsigned long vmi_setup_cycles;

unsigned long vmi_handle_trap(struct rec *rec, unsigned long esr,
			      unsigned long hpfar);
unsigned long vmi_restore_trap(struct rec *rec);
#endif /* CONFIG_RMM_VMI */

#endif /* VMI_H */
