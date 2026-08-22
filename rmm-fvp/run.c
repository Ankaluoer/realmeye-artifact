/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <arch.h>
#include <atomics.h>
#include <buffer.h>
#include <debug.h>
#include <esr.h>
#include <exit.h>
#include <gic.h>
#include <granule.h>
#include <inject_exp.h>
#include <psci.h>
#include <realm.h>
#include <rec.h>
#include <rsi-host-call.h>
#include <rsi_rdev_call.h>
#include <smc-handler.h>
#include <smc-rmi.h>
#include <smc-rsi.h>
#include <smc.h>
#include <string.h>
#include <s2tt.h>
#include <s2tt_ap.h>

/* ===== Minimal AES-128-ECB for VMI result encryption ===== */
static const unsigned char vmi_aes_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char vmi_aes_rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static void vmi_aes_key_expansion(const unsigned char *key, unsigned char *round_keys)
{
        unsigned int i;
        unsigned char temp[4];

        for (i = 0; i < 16; i++)
                round_keys[i] = key[i];

        for (i = 4; i < 44; i++) {
                temp[0] = round_keys[(i-1)*4+0];
                temp[1] = round_keys[(i-1)*4+1];
                temp[2] = round_keys[(i-1)*4+2];
                temp[3] = round_keys[(i-1)*4+3];
                if (i % 4 == 0) {
                        unsigned char t = temp[0];
                        temp[0] = vmi_aes_sbox[temp[1]] ^ vmi_aes_rcon[i/4];
                        temp[1] = vmi_aes_sbox[temp[2]];
                        temp[2] = vmi_aes_sbox[temp[3]];
                        temp[3] = vmi_aes_sbox[t];
                }
                round_keys[i*4+0] = round_keys[(i-4)*4+0] ^ temp[0];
                round_keys[i*4+1] = round_keys[(i-4)*4+1] ^ temp[1];
                round_keys[i*4+2] = round_keys[(i-4)*4+2] ^ temp[2];
                round_keys[i*4+3] = round_keys[(i-4)*4+3] ^ temp[3];
        }
}

static unsigned char vmi_gf_mul2(unsigned char x)
{
        return (unsigned char)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* Forward declaration: defined later in this file */
static unsigned long vmi_va_to_pa(struct rec *rec, unsigned long va,
                                  unsigned long ttbr, unsigned long *out_pa);

static unsigned long vmi_read_pa(struct rec *rec, unsigned long ipa,
                                 unsigned long *out_val); 

/* ===== Performance measurement infrastructure ===== */
static inline unsigned long perf_cycles(void)
{
    unsigned long v;
    asm volatile("isb; mrs %0, cntpct_el0" : "=r"(v));
    return v;
}

static void vmi_aes_encrypt_block(const unsigned char *in, unsigned char *out,
                                   const unsigned char *round_keys)
{
        unsigned char state[16];
        unsigned int i, round;

        for (i = 0; i < 16; i++)
                state[i] = in[i] ^ round_keys[i];

        for (round = 1; round <= 10; round++) {
                unsigned char tmp[16];
                /* SubBytes */
                for (i = 0; i < 16; i++)
                        state[i] = vmi_aes_sbox[state[i]];
                /* ShiftRows */
                tmp[0]=state[0]; tmp[1]=state[5]; tmp[2]=state[10]; tmp[3]=state[15];
                tmp[4]=state[4]; tmp[5]=state[9]; tmp[6]=state[14]; tmp[7]=state[3];
                tmp[8]=state[8]; tmp[9]=state[13]; tmp[10]=state[2]; tmp[11]=state[7];
                tmp[12]=state[12]; tmp[13]=state[1]; tmp[14]=state[6]; tmp[15]=state[11];
                /* MixColumns (skip in last round) */
                if (round < 10) {
                        for (i = 0; i < 16; i += 4) {
                                unsigned char a=tmp[i],b=tmp[i+1],c=tmp[i+2],d=tmp[i+3];
                                state[i]   = vmi_gf_mul2(a)^vmi_gf_mul2(b)^b^c^d;
                                state[i+1] = a^vmi_gf_mul2(b)^vmi_gf_mul2(c)^c^d;
                                state[i+2] = a^b^vmi_gf_mul2(c)^vmi_gf_mul2(d)^d;
                                state[i+3] = vmi_gf_mul2(a)^a^b^c^vmi_gf_mul2(d);
                        }
                } else {
                        for (i = 0; i < 16; i++)
                                state[i] = tmp[i];
                }
                /* AddRoundKey */
                for (i = 0; i < 16; i++)
                        state[i] ^= round_keys[round*16+i];
        }
        for (i = 0; i < 16; i++)
                out[i] = state[i];
}

/* Pre-shared key (prototype: hardcoded, production: via attestation key exchange) */
static const unsigned char vmi_psk[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
};

static void vmi_encrypt_result(unsigned long proc_count, unsigned long status,
                                unsigned char *out_cipher)
{
        unsigned char plaintext[16];
        unsigned char round_keys[176];
        unsigned int i;

        /* Pack proc_count and status into 16 bytes */
        for (i = 0; i < 8; i++) {
                plaintext[i] = (unsigned char)(proc_count >> (i * 8));
                plaintext[i+8] = (unsigned char)(status >> (i * 8));
        }

        vmi_aes_key_expansion(vmi_psk, round_keys);
        vmi_aes_encrypt_block(plaintext, out_cipher, round_keys);
}

static void perf_test_aes(void)
{
    unsigned char in[16], out[16];
    unsigned char round_keys[176];
    unsigned long t1, t2;
    int i;

    /* Init test data and keys (don't measure key expansion) */
    for (i = 0; i < 16; i++)
        in[i] = (unsigned char)i;
    vmi_aes_key_expansion(vmi_psk, round_keys);

    /* Run 1010 iterations: first 10 warmup (discarded), then 1000 measured */
    for (i = 0; i < 1010; i++) {
        t1 = perf_cycles();
        vmi_aes_encrypt_block(in, out, round_keys);
        t2 = perf_cycles();
        if (i >= 10)
            ERROR("PERF,aes_encrypt_block,%lu\n", t2 - t1);
    }
}

/* ===== End AES-128 ===== */

static void perf_test_va_to_pa(struct rec *rec)
{
    struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
    unsigned long ttbr1 = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
    unsigned long current = sysregs->pp_sysregs.sp_el0;
    unsigned long pa = 0;
    unsigned long t1, t2, ret;
    int i;

    /* Sanity check: target VA must be a kernel address */
    if (current < 0xffff000000000000UL) {
        ERROR(">>> PERF va_to_pa: invalid current VA 0x%lx <<<\n", current);
        return;
    }

    /* Run 1010 iterations: first 10 warmup (discarded), then 1000 measured */
    for (i = 0; i < 1010; i++) {
        t1 = perf_cycles();
        ret = vmi_va_to_pa(rec, current, ttbr1, &pa);
        t2 = perf_cycles();
        if (i >= 10) {
            if (ret == 0UL)
                ERROR("PERF,va_to_pa,%lu\n", t2 - t1);
            else
                ERROR("PERF,va_to_pa,FAIL,%lu\n", ret);
        }
    }
}

static void perf_test_read_pa(struct rec *rec)
{
    struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
    unsigned long ttbr1 = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
    unsigned long current = sysregs->pp_sysregs.sp_el0;
    unsigned long pa = 0, val = 0;
    unsigned long t1, t2, ret;
    int i;

    if (current < 0xffff000000000000UL) {
        ERROR(">>> PERF read_pa: invalid current VA 0x%lx <<<\n", current);
        return;
    }

    /* First translate current VA to PA (one-shot, not measured) */
    ret = vmi_va_to_pa(rec, current, ttbr1, &pa);
    if (ret != 0UL) {
        ERROR(">>> PERF read_pa: va_to_pa failed ret=%lu <<<\n", ret);
        return;
    }

    /* Run 1010 iterations: first 10 warmup, then 1000 measured */
    for (i = 0; i < 1010; i++) {
        t1 = perf_cycles();
        ret = vmi_read_pa(rec, pa, &val);
        t2 = perf_cycles();
        if (i >= 10) {
            if (ret == 0UL)
                ERROR("PERF,read_pa,%lu\n", t2 - t1);
            else
                ERROR("PERF,read_pa,FAIL,%lu\n", ret);
        }
    }
}

static void perf_test_p1(struct rec *rec)
{
    struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
    unsigned long ttbr1 = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
    unsigned long start_task = sysregs->pp_sysregs.sp_el0;
    unsigned long tasks_off = 0x400UL;
    unsigned long pid_off = 0x4D0UL;
    unsigned long comm_off = 0x6B8UL;
    unsigned long pa = 0, val = 0, ret;
    int iter, count;
    unsigned long t1, t2;

    if (start_task < 0xffff000000000000UL) {
        ERROR(">>> PERF p1: invalid start_task 0x%lx <<<\n", start_task);
        return;
    }

    /* 55 iterations: first 5 warmup (discarded), then 50 measured */
    for (iter = 0; iter < 55; iter++) {
        t1 = perf_cycles();

        unsigned long task = start_task;
        ret = vmi_va_to_pa(rec, task, ttbr1, &pa);
        if (ret != 0UL) {
            t2 = perf_cycles();
            if (iter >= 5)
                ERROR("PERF,p1_scan,FAIL,start_xlat,%lu\n", t2 - t1);
            continue;
        }

        for (count = 0; count < 200; count++) {
            unsigned long c1 = 0, c2 = 0;
            int pid_v = 0;

            /* Read comm (16 bytes) */
            ret = vmi_va_to_pa(rec, task + comm_off, ttbr1, &pa);
            if (ret == 0UL) vmi_read_pa(rec, pa, &c1);
            ret = vmi_va_to_pa(rec, task + comm_off + 8, ttbr1, &pa);
            if (ret == 0UL) vmi_read_pa(rec, pa, &c2);

            /* Read pid */
            ret = vmi_va_to_pa(rec, task + pid_off, ttbr1, &pa);
            if (ret == 0UL) {
                vmi_read_pa(rec, pa, &val);
                pid_v = (int)(val & 0xFFFFFFFF);
            }

            /* Suppress unused-but-set warning */
            (void)c1; (void)c2; (void)pid_v;

            /* Walk to next task via tasks list */
            unsigned long next_t;
            ret = vmi_va_to_pa(rec, task + tasks_off, ttbr1, &pa);
            if (ret != 0UL) break;
            vmi_read_pa(rec, pa, &next_t);
            unsigned long next_task = next_t - tasks_off;
            if (next_task == start_task || count >= 49) {
                count++;
                break;
            }
            task = next_task;
        }

        t2 = perf_cycles();
        if (iter >= 5)
            ERROR("PERF,p1_scan,%lu,procs,%d\n", t2 - t1, count);
    }
}

static void perf_test_p5(struct rec *rec)
{
    struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
    unsigned long ttbr1 = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
    unsigned long vbar = sysregs->pp_sysregs.vbar_el1;
    unsigned long stext, scan_start, scan_end, code_lo, code_hi;
    unsigned long sct_va = 0;
    unsigned long pa = 0, val = 0, ret;
    unsigned long addr;
    unsigned long t1, t2;
    int found = 0;

    if (vbar < 0xffff000000000000UL) {
        ERROR(">>> PERF p5: invalid vbar 0x%lx <<<\n", vbar);
        return;
    }

    stext = vbar - 0x800UL;
    scan_start = stext + 0x1400000UL;
    scan_end = stext + 0x1500000UL;
    code_lo = stext;
    code_hi = stext + 0x1500000UL;

    ERROR(">>> PERF p5: starting scan vbar=0x%lx range=[0x%lx, 0x%lx) <<<\n",
            vbar, scan_start, scan_end);

    t1 = perf_cycles();

    /* Scan for sys_call_table: 8 consecutive kernel text pointers */
    for (addr = scan_start; addr < scan_end; addr += 8UL) {
        int good = 0;
        int k;
        for (k = 0; k < 8; k++) {
            ret = vmi_va_to_pa(rec, addr + (unsigned long)k * 8UL, ttbr1, &pa);
            if (ret != 0UL) break;
            vmi_read_pa(rec, pa, &val);
            if (val >= code_lo && val < code_hi) {
                good++;
            } else {
                break;
            }
        }
        if (good == 8) {
            sct_va = addr;
            found = 1;
            break;
        }
    }

    t2 = perf_cycles();

    if (found)
        ERROR("PERF,p5_scan,%lu,sct_va,0x%lx\n", t2 - t1, sct_va);
    else
        ERROR("PERF,p5_scan,FAIL,%lu\n", t2 - t1);
}

/* ===== VMI R3: Page Trap Global State ===== */
bool vmi_trap_enabled = false;
unsigned long vmi_trap_ipa = 0UL;
bool vmi_trap_fired = false;
static bool r3_trap_setup_done = false;
static bool r3_restore_pending = false;
static unsigned long r3_original_s2tte = 0UL;

/* ===== VMI Helper: Stage-1 page table walk ===== */
static unsigned long vmi_read_pa(struct rec *rec, unsigned long ipa,
				 unsigned long *out_val)
{
	struct s2_walk_result walk_res;
	enum s2_walk_status ws;
	struct granule *gr;
	unsigned long *page_ptr;
	unsigned long offset;

	ws = realm_ipa_to_pa(rec, ipa & GRANULE_MASK, &walk_res);
	if (ws != WALK_SUCCESS) {
		return 1UL;
	}

	gr = find_granule(walk_res.pa);
	page_ptr = (unsigned long *)buffer_granule_mecid_map(
		gr, SLOT_REALM, rec->realm_info.primary_s2_ctx.mecid);
	if (page_ptr == NULL) {
		granule_unlock(walk_res.llt);
		return 2UL;
	}

	offset = (ipa & ~GRANULE_MASK) / sizeof(unsigned long);
	*out_val = page_ptr[offset];

	buffer_unmap(page_ptr);
	granule_unlock(walk_res.llt);
	return 0UL;
}

static unsigned long vmi_va_to_pa(struct rec *rec, unsigned long va,
				  unsigned long ttbr, unsigned long *out_pa)
{
	unsigned long l0_idx, l1_idx, l2_idx, l3_idx;
	unsigned long entry  = 0UL, table_ipa;
	unsigned long ret;

	/* Extract indices from VA */
	l0_idx = (va >> 39) & 0x1FF;
	l1_idx = (va >> 30) & 0x1FF;
	l2_idx = (va >> 21) & 0x1FF;
	l3_idx = (va >> 12) & 0x1FF;

	/* L0 walk */
        table_ipa = ttbr & 0x0000FFFFFFFFF000UL;
        ret = vmi_read_pa(rec, table_ipa + l0_idx * 8, &entry);
        if (ret != 0UL || (entry & 0x3) != 0x3) {
                return 1UL;
        }

	/* L1 walk */
	table_ipa = entry & 0x0000FFFFFFFFF000UL;
	ret = vmi_read_pa(rec, table_ipa + l1_idx * 8, &entry);
	if (ret != 0UL) {
		return 2UL;
	}
	/* Check for L1 block mapping (1GB) */
	if ((entry & 0x3) == 0x1) {
		*out_pa = (entry & 0x0000FFFFC0000000UL) | (va & 0x3FFFFFFFUL);
		return 0UL;
	}
	if ((entry & 0x3) != 0x3) {
		return 2UL;
	}

	/* L2 walk */
	table_ipa = entry & 0x0000FFFFFFFFF000UL;
	ret = vmi_read_pa(rec, table_ipa + l2_idx * 8, &entry);
	if (ret != 0UL) {
		return 3UL;
	}
	/* Check for L2 block mapping (2MB) */
	if ((entry & 0x3) == 0x1) {
		*out_pa = (entry & 0x0000FFFFFFE00000UL) | (va & 0x1FFFFFUL);
		return 0UL;
	}
	if ((entry & 0x3) != 0x3) {
		return 3UL;
	}

	/* L3 walk */
	table_ipa = entry & 0x0000FFFFFFFFF000UL;
	ret = vmi_read_pa(rec, table_ipa + l3_idx * 8, &entry);
	if (ret != 0UL) {
		return 4UL;
	}
	/* L3 entry: [1:0] must be 0b11 for valid page */
	if ((entry & 0x3) != 0x3) {
		return 4UL;
	}
	*out_pa = (entry & 0x0000FFFFFFFFF000UL) | (va & 0xFFFUL);
	return 0UL;
}

static void reset_last_run_info(struct rec_plane *plane)
{
	plane->last_run_info.esr = 0UL;
}

static bool complete_mmio_emulation(struct rec *rec, struct rmi_rec_enter *rec_enter)
{
	struct rec_plane *plane = rec_active_plane(rec);
	unsigned long esr = plane->last_run_info.esr;
	unsigned int rt = esr_srt(esr);

	if ((rec_enter->flags & REC_ENTRY_FLAG_EMUL_MMIO) == 0UL) {
		return true;
	}

	/*
	 * If INJECT_SEA is set, we will only reach here if the condition
	 * for that flag is satisfied and has an effect on the Realm viz to
	 * Inject Data Abort at Unprotected IPA. Hence we skip EMUL_MMIO
	 * if the INJECT_SEA flag is set.
	 */
	if ((rec_enter->flags & REC_ENTRY_FLAG_INJECT_SEA) != 0UL) {
		return true;
	}

	/*
	 * The ISV bit is cleared as part of REC exit if the original data
	 * abort was not meant to be emulatable, i.e the address is either
	 * in PAR or is an AArch32 abort.
	 */
	if (((esr & MASK(ESR_EL2_EC)) != ESR_EL2_EC_DATA_ABORT) ||
	    ((esr & ESR_EL2_ABORT_ISV_BIT) == 0UL)) {
		/*
		 * MMIO emulation is requested but the REC did not exit with
		 * an emulatable exit.
		 */
		return false;
	}

	/*
	 * Emulate mmio read (unless the load is to xzr)
	 */
	if (!esr_is_write(esr) && (rt != 31U)) {
		unsigned long val;

		val = rec_enter->gprs[0] & access_mask(esr);

		if (esr_sign_extend(esr)) {
			unsigned int bit_count = access_len(esr) * 8U;
			unsigned long mask = (UL(1)) << U(bit_count - 1U);

			val = (val ^ mask) - mask;
			if (!esr_sixty_four(esr)) {
				val &= (1UL << 32U) - 1UL;
			}
		}

		plane->regs[rt] = val;
	}

	plane->pc = plane->pc + 4UL;
	return true;
}

static void complete_set_ripas(struct rec *rec)
{
	struct rec_plane *plane = rec_plane_0(rec);
	enum ripas ripas_val = rec->set_ripas.ripas_val;

	if (rec->set_ripas.base == rec->set_ripas.top) {
		return;
	}

	/* RIPAS change request can only come from the Plane 0. */
	assert(rec_is_plane_0_active(rec));

	/* Pending request from Realm */
	plane->regs[0] = RSI_SUCCESS;
	plane->regs[1] = rec->set_ripas.addr;

	if ((ripas_val == RIPAS_RAM) && (rec->set_ripas.addr != rec->set_ripas.top)
		 && (rec->set_ripas.response == REJECT)) {
		plane->regs[2] = RSI_REJECT;
	} else {
		plane->regs[2] = RSI_ACCEPT;
	}

	rec->set_ripas.base = 0UL;
	rec->set_ripas.top = 0UL;
}

static void complete_dev_mem_mapping(struct rec *rec,
				     struct rmi_rec_enter *rec_enter)
{
	enum host_response response;
	struct rec_plane *plane = rec_plane_0(rec);

	/* Is dev mem map in progress */
	if (rec->dev_mem.base == 0UL) {
		return;
	}

	/* Pending request from Realm */
	plane->regs[0] = RSI_SUCCESS;
	plane->regs[1] = rec->dev_mem.addr;

	/* Dev memory validate request can only come from Plane 0. */
	assert(rec_is_plane_0_active(rec));

	if ((rec_enter->flags & REC_ENTRY_FLAG_DEV_MEM_RESPONSE) == 0UL) {
		response = ACCEPT;
	} else {
		response = REJECT;
	}

	if ((rec->dev_mem.addr != rec->dev_mem.top) && (response == REJECT)) {
		plane->regs[2] = RSI_REJECT;
	} else {
		plane->regs[2] = RSI_ACCEPT;
	}

	rec->dev_mem.base = 0UL;
	rec->dev_mem.top = 0UL;
}

static void complete_set_s2ap(struct rec *rec)
{
	struct rec_plane *plane = rec_plane_0(rec);
	bool rtt_tree_pp;
	unsigned long new_base;
	unsigned long cookie = 0UL;

	if ((rec->set_s2ap.base == 0UL) && (rec->set_s2ap.top == 0UL)) {
		/* No S2AP index change pending. Just return */
		return;
	}

	/* S2AP change request can only come from Plane 0. */
	assert(rec_is_plane_0_active(rec));

	rtt_tree_pp = rec->realm_info.rtt_tree_pp;

	if (rec->set_s2ap.response != REJECT) {
		struct rd *rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);

		assert(rd != NULL);

		set_perm_immutable(rd, rec->set_s2ap.index);

		buffer_unmap(rd);
	}

	new_base = rec->set_s2ap.base;
	if (rtt_tree_pp) {
		/*
		 * If we have updated the whole range of IPAs for the current
		 * tree, we need to verify if there are pending RTT trees to
		 * update and then create a new cookie to track the progress to
		 * the next tree starting at base IPA.
		 *
		 * If, on the other hand, we haven't updated the whole range of
		 * IPAs for the current tree, update the cookie with the new
		 * base and the current tree index.
		 *
		 * Note that the current cookie contains the base addr and the
		 * tree index from the last RSI_MEM_SET_PERM_INDEX call.
		 */
		unsigned long next_s2tt_idx;

		cookie = rec->set_s2ap.cookie;
		next_s2tt_idx = GET_RTT_IDX_FROM_COOKIE(cookie);
		assert(next_s2tt_idx < rec_num_planes(rec));

		if (new_base == rec->set_s2ap.top) {
			next_s2tt_idx++;

			if (next_s2tt_idx < rec_num_planes(rec)) {
				/*
				 * The current cookie should have the value
				 * of the original base, which will be used to
				 * create a new cookie to point to the base of
				 * the next RTT tree.
				 */
				new_base = GET_RTT_BASE_FROM_COOKIE(cookie);
				cookie = RTT_COOKIE_CREATE(new_base,
								  next_s2tt_idx);
			} else {
				/*
				 * Reset the cookie if we
				 * updated all the trees.
				 */
				cookie = 0UL;
			}
		} else {
			cookie = RTT_COOKIE_CREATE(new_base, next_s2tt_idx);
		}
	}

	rec->set_s2ap.base = 0UL;
	rec->set_s2ap.top = 0UL;
	rec->set_s2ap.index = 0UL;
	rec->set_s2ap.cookie = 0UL;

	plane->regs[0] = RSI_SUCCESS;
	plane->regs[1] = new_base;
	plane->regs[2] = (unsigned long)rec->set_s2ap.response;
	plane->regs[3] = cookie;
}

static bool complete_sea_insertion(struct rec *rec, struct rmi_rec_enter *rec_enter)
{
	struct rec_plane *plane = rec_active_plane(rec);
	unsigned long esr = plane->last_run_info.esr;
	unsigned long fipa;
	unsigned long hpfar = plane->last_run_info.hpfar;

	if ((rec_enter->flags & REC_ENTRY_FLAG_INJECT_SEA) == 0UL) {
		return true;
	}

	if ((esr & MASK(ESR_EL2_EC)) != ESR_EL2_EC_DATA_ABORT) {
		return false;
	}

	fipa = (hpfar & MASK(HPFAR_EL2_FIPA)) << HPFAR_EL2_FIPA_OFFSET;
	if (addr_in_rec_par(rec, fipa)) {
		return false;
	}

	inject_sync_idabort_rec(rec, ESR_EL2_ABORT_FSC_SEA);
	return true;
}


static void complete_sysreg_emulation(struct rec *rec, struct rmi_rec_enter *rec_enter)
{
	struct rec_plane *plane = rec_active_plane(rec);
	unsigned long esr = plane->last_run_info.esr;

	/* Rt bits [9:5] of ISS field cannot exceed 0b11111 */
	unsigned int rt = (unsigned int)ESR_EL2_SYSREG_ISS_RT(esr);

	if ((esr & MASK(ESR_EL2_EC)) != ESR_EL2_EC_SYSREG) {
		return;
	}

	if (ESR_EL2_SYSREG_IS_WRITE(esr)) {
		return;
	}

	/* Handle xzr */
	if (rt != 31U) {
		plane->regs[rt] = rec_enter->gprs[0];
	}
}

static bool complete_host_call(struct rec *rec, struct rmi_rec_run *rec_run)
{
	struct rsi_walk_result walk_result;

	if (!rec->host_call) {
		return true;
	}

	walk_result = complete_rsi_host_call(rec, &rec_run->enter);

	if (walk_result.abort) {
		/*
		 * The IPA where the result should be copied to (referred to by
		 * X1 at RSI_HOST_CALL) has RAM ripas but invalid mapping.
		 * Emulate the data abort against that IPA so that the host
		 * can bring the page in.
		 */
		unsigned long ipa = rec_active_plane(rec)->regs[1];

		emulate_stage2_data_abort(&rec_run->exit,
					  walk_result.rtt_level, ipa);
		return false;
	}

	rec->host_call = false;
	return true;
}

unsigned long smc_rec_enter(unsigned long rec_addr,
			    unsigned long rec_run_addr)
{
	struct granule *g_rec;
	struct granule *g_run;
	struct rec *rec;
	struct rec_plane *plane;
	STRUCT_TYPE sysreg_state *sysregs;
	struct rd *rd;
	struct rmi_rec_run rec_run;
	unsigned long realm_state, ret;
	bool success;
	int res;
	void *rec_aux;

	/*
	 * The content of `rec_run.exit` shall be returned to the host.
	 * Zero the structure to avoid the leakage of
	 * the content of the RMM's stack.
	 */
	(void)memset(&rec_run.exit, 0, sizeof(struct rmi_rec_exit));

	g_run = find_granule(rec_run_addr);
	if ((g_run == NULL) ||
		(granule_unlocked_state(g_run) != GRANULE_STATE_NS)) {
		return RMI_ERROR_INPUT;
	}

	/* For a REC to be runnable, it should be unused (refcount = 0) */
	res = find_lock_unused_granule(rec_addr, GRANULE_STATE_REC, &g_rec);
	if (res != 0) {
		switch (res) {
		case -EINVAL:
			return RMI_ERROR_INPUT;
		default:
			assert(res == -EBUSY);
			return RMI_ERROR_REC;
		}
	}

	/*
	 * Increment refcount. REC can have lock-free access, thus atomic access
	 * is required. Also, since the granule is only used for refcount
	 * update, only an atomic operation will suffice and release/acquire
	 * semantics are not required.
	 */
	atomic_granule_get(g_rec);

	/* Unlock the granule before switching to realm world. */
	granule_unlock(g_rec);

	success = ns_buffer_read(SLOT_NS, g_run, 0U,
				 sizeof(struct rmi_rec_enter), &rec_run.enter);

	if (!success) {
		/*
		 * Decrement refcount. Lock-free access to REC, thus atomic and
		 * release semantics is required.
		 */
		atomic_granule_put_release(g_rec);
		return RMI_ERROR_INPUT;
	}

	rec = buffer_granule_map(g_rec, SLOT_REC);
	assert(rec != NULL);

	rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	assert(rd != NULL);

	realm_state = get_rd_state_unlocked(rd);
	buffer_unmap(rd);

	switch (realm_state) {
	case REALM_NEW:
		ret = pack_return_code(RMI_ERROR_REALM, 0U);
		goto out_unmap_buffers;
	case REALM_ACTIVE:
		break;
	case REALM_SYSTEM_OFF:
		ret = pack_return_code(RMI_ERROR_REALM, 1U);
		goto out_unmap_buffers;
	default:
		assert(false);
		break;
	}

	if (!rec->runnable) {
		ret = RMI_ERROR_REC;
		goto out_unmap_buffers;
	}

	/* REC with pending command is not schedulable */
	if (rec->pending_op != REC_PENDING_NONE) {
		assert((rec->pending_op == REC_PENDING_PSCI_COMPLETE) ||
		       (rec->pending_op == REC_PENDING_VDEV_COMPLETE));
		ret = RMI_ERROR_REC;
		goto out_unmap_buffers;
	}

	/* Map auxiliary granules */
	rec_aux = buffer_rec_aux_granules_map(rec->g_aux, rec->num_rec_aux);

	/* VMI: check if Host requested a process scan via flags */
        if (rec_run.enter.flags & (1UL << 63)) {
                /* Check if this is a fine-grained VMI command */
            if (rec_run.enter.gprs[0] > 0) {
                unsigned long vmi_cmd = rec_run.enter.gprs[0];
                unsigned long vmi_arg0 = rec_run.enter.gprs[1];
                struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
                unsigned long vmi_result = 0;

                switch (vmi_cmd) {
                case 1: { /* READ_PA */
                    unsigned long val;
                    if (vmi_read_pa(rec, vmi_arg0, &val) == 0UL) {
                        vmi_result = val;
                        ERROR(">>> VMI_CMD[READ_PA] addr=0x%lx val=0x%lx <<<\n", vmi_arg0, val);
                    } else {
                        ERROR(">>> VMI_CMD[READ_PA] addr=0x%lx FAILED <<<\n", vmi_arg0);
                    }
                    break;
                }
                case 2: { /* READ_VA */
                    unsigned long ttbr1 = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
                    unsigned long pa, val;
                    if (vmi_va_to_pa(rec, vmi_arg0, ttbr1, &pa) == 0UL &&
                        vmi_read_pa(rec, pa, &val) == 0UL) {
                        vmi_result = val;
                        ERROR(">>> VMI_CMD[READ_VA] va=0x%lx pa=0x%lx val=0x%lx <<<\n", vmi_arg0, pa, val);
                    } else {
                        ERROR(">>> VMI_CMD[READ_VA] va=0x%lx FAILED <<<\n", vmi_arg0);
                    }
                    break;
                }
                case 3: { /* GET_VCPUREG */
                    unsigned long reg_val = 0;
                    switch (vmi_arg0) {
                    case 0: reg_val = (unsigned long)sysregs->pp_sysregs.ttbr0_el1.lo; break;
                    case 1: reg_val = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo; break;
                    case 2: reg_val = sysregs->pp_sysregs.sp_el0; break;
                    case 3: reg_val = (unsigned long)sysregs->pp_sysregs.tcr_el1; break;
                    case 4: reg_val = (unsigned long)sysregs->pp_sysregs.sctlr_el1; break;
                    case 5: reg_val = (unsigned long)sysregs->pp_sysregs.vbar_el1; break;
                    default: break;
                    }
                    vmi_result = reg_val;
                    ERROR(">>> VMI_CMD[GET_REG] reg=%lu val=0x%lx <<<\n", vmi_arg0, reg_val);
                    break;
                }
                case 100: { /* PERF_AES — run AES microbench */
                    perf_test_aes();
                    vmi_result = 0;
                    ERROR(">>> VMI_CMD[PERF_AES] done <<<\n");
                    break;
                }
		case 101: { /* PERF_VA_TO_PA */
                    perf_test_va_to_pa(rec);
                    vmi_result = 0;
                    ERROR(">>> VMI_CMD[PERF_VA_TO_PA] done <<<\n");
                    break;
                }
		case 102: { /* PERF_READ_PA */
                    perf_test_read_pa(rec);
                    vmi_result = 0;
                    ERROR(">>> VMI_CMD[PERF_READ_PA] done <<<\n");
                    break;
                }
		case 103: { /* PERF_P1 */
                    perf_test_p1(rec);
                    vmi_result = 0;
                    ERROR(">>> VMI_CMD[PERF_P1] done <<<\n");
                    break;
                }
		case 104: { /* PERF_P5 */
                    perf_test_p5(rec);
                    vmi_result = 0;
                    ERROR(">>> VMI_CMD[PERF_P5] done <<<\n");
                    break;
                }
		default:
                    ERROR(">>> VMI_CMD[%lu] unknown command <<<\n", vmi_cmd);
                    break;
                }

                rec_run.exit.gprs[0] = vmi_result;
        	rec_run.exit.exit_reason = RMI_EXIT_HOST_CALL;        
		rec_run.enter.flags &= ~(1UL << 63);
		rec_run.enter.gprs[0] = 0;
                rec_run.enter.gprs[1] = 0;
		ret = RMI_SUCCESS;
                ERROR(">>> VMI_CMD goto out, ret=%lu, exit.gprs[0]=0x%lx <<<\n", ret, rec_run.exit.gprs[0]);
		goto out_unmap_aux_granules;
            } else {
		STRUCT_TYPE sysreg_state *vmi_sysregs = rec_active_plane_sysregs(rec);
                unsigned long vmi_ttbr1 = (unsigned long)vmi_sysregs->pp_sysregs.ttbr1_el1.lo;
                unsigned long vmi_current = vmi_sysregs->pp_sysregs.sp_el0;
                unsigned long tasks_off = 0x400UL;
                unsigned long pid_off = 0x4D0UL;
                unsigned long comm_off = 0x6B8UL;
                unsigned long pa_r, val_r, ret_r;

                ERROR(">>> VMI_SCAN[RMI]: triggered by Host flag, current_task=0x%lx ttbr1=0x%lx <<<\n",
                        vmi_current, vmi_ttbr1);

                ret_r = vmi_va_to_pa(rec, vmi_current, vmi_ttbr1, &pa_r);
                if (ret_r == 0UL) {
                        unsigned long task = vmi_current;
                        int count;
                        for (count = 0; count < 200; count++) {
                                unsigned long c1 = 0, c2 = 0;
                                ret_r = vmi_va_to_pa(rec, task + comm_off, vmi_ttbr1, &pa_r);
                                if (ret_r == 0UL) { vmi_read_pa(rec, pa_r, &c1); }
                                ret_r = vmi_va_to_pa(rec, task + comm_off + 8, vmi_ttbr1, &pa_r);
                                if (ret_r == 0UL) { vmi_read_pa(rec, pa_r, &c2); }
                                int pid_v = 0;
                                ret_r = vmi_va_to_pa(rec, task + pid_off, vmi_ttbr1, &pa_r);
                                if (ret_r == 0UL) {
                                        vmi_read_pa(rec, pa_r, &val_r);
                                        pid_v = (int)(val_r & 0xFFFFFFFF);
                                }
                                ERROR(">>> VMI_SCAN PROC[%d] pid=%d comm=%.8s%.8s <<<\n",
                                        count, pid_v, (char*)&c1, (char*)&c2);
				unsigned long next_t;
                                ret_r = vmi_va_to_pa(rec, task + tasks_off, vmi_ttbr1, &pa_r);
                                if (ret_r == 0UL) {
                                        vmi_read_pa(rec, pa_r, &next_t);
                                        unsigned long next_task = next_t - tasks_off;
                                        if (next_task == vmi_current || count >= 49) {
                                                ERROR(">>> VMI_SCAN: === Total: %d processes === <<<\n", count + 1);
                                                
						vmi_encrypt_result((unsigned long)(count + 1), 1UL, rec_run.exit.vmi_encrypted);

						break;
                                        }
                                        task = next_task;
                                } else {
                                        break;
                                }
                        }
                } else {
                        ERROR(">>> VMI_SCAN[RMI]: VA translate failed <<<\n");
                	vmi_encrypt_result(0UL, 2UL, rec_run.exit.vmi_encrypted);
		}

		/* ===== P5: Syscall Table Hook Detection ===== */
                {
                        unsigned long vmi_vbar = vmi_sysregs->pp_sysregs.vbar_el1;
                        unsigned long stext = vmi_vbar - 0x800UL;
                        unsigned long scan_start = stext + 0x1400000UL;
                        unsigned long scan_end   = stext + 0x1500000UL;
                        unsigned long code_lo = stext;
                        unsigned long code_hi = stext + 0x1500000UL;
                        unsigned long sct_va = 0;
                        unsigned long pa_tmp, val_tmp;
                        int hooks_found = 0;

                        ERROR(">>> VMI_SCAN[P5]: vbar=0x%lx stext=0x%lx scanning 0x%lx-0x%lx <<<\n",
                                vmi_vbar, stext, scan_start, scan_end);

                        /* Scan for sys_call_table: 8 consecutive kernel text pointers */
                        for (unsigned long addr = scan_start; addr < scan_end; addr += 8UL) {
                                int good = 0;
                                for (int k = 0; k < 8; k++) {
                                        ret_r = vmi_va_to_pa(rec, addr + (unsigned long)k * 8UL, vmi_ttbr1, &pa_tmp);
                                        if (ret_r != 0UL) break;
                                        vmi_read_pa(rec, pa_tmp, &val_tmp);
                                        if (val_tmp >= code_lo && val_tmp < code_hi) {
                                                good++;
                                        } else {
                                                break;
                                        }
                                }
                                if (good == 8) {
                                        sct_va = addr;
                                        ERROR(">>> VMI_SCAN[P5]: Found sys_call_table at 0x%lx <<<\n", sct_va);
                                        break;
                                }
                        }

                        if (sct_va != 0UL) {
                                /* Also find _etext: sct is shortly after _etext */
                                unsigned long etext = sct_va & ~0xFFFUL; /* align down to page */
                                int check_nrs[] = {61, 129};
                                int num_checks = 2;

                                for (int ci = 0; ci < num_checks; ci++) {
                                        unsigned long entry_va = sct_va + (unsigned long)check_nrs[ci] * 8UL;
                                        unsigned long entry_pa, func_ptr;

                                        ret_r = vmi_va_to_pa(rec, entry_va, vmi_ttbr1, &entry_pa);
                                        if (ret_r == 0UL) {
                                                vmi_read_pa(rec, entry_pa, &func_ptr);

                                                if (func_ptr < code_lo || func_ptr >= etext) {
                                                        ERROR(">>> VMI_SCAN[P5]: HOOK DETECTED! syscall[%d] -> 0x%lx <<<\n",
                                                                check_nrs[ci], func_ptr);
                                                        hooks_found++;
                                                } else {
                                                        ERROR(">>> VMI_SCAN[P5]: syscall[%d] -> 0x%lx (OK) <<<\n",
                                                                check_nrs[ci], func_ptr);
                                                }
                                        } else {
                                                ERROR(">>> VMI_SCAN[P5]: Failed to read syscall[%d] <<<\n", check_nrs[ci]);
                                        }
                                }
                                ERROR(">>> VMI_SCAN[P5]: === %d hooks detected === <<<\n", hooks_found);
                        } else {
                                ERROR(">>> VMI_SCAN[P5]: sys_call_table NOT FOUND in scan range <<<\n");
                        }
                }

                /* Clear the flag so it doesn't trigger again */
                rec_run.enter.flags &= ~(1UL << 63);
		} /* end of else (full scan) */
        }

	/*
	 * Check GIC state after checking other conditions but before doing
	 * anything which may have side effects.
	 */
	if (!gic_validate_state(rec_run.enter.gicv3_hcr,
				&rec_run.enter.gicv3_lrs[0])) {
		ret = RMI_ERROR_REC;
		goto out_unmap_aux_granules;
	}

	/*
	 * Note that the order of checking SEA insertion needs to be prior
	 * to checking mmio emulation as the conditions for the former flag
	 * having an effect (Data Abort at Unprotected IPA) are a superset
	 * of those for RMI_EMULATED_MMIO (Data Abort at Unprotected IPA and
	 * access was an emulatable read).
	 */
	if (!complete_sea_insertion(rec, &rec_run.enter)) {
		ret = RMI_ERROR_REC;
		goto out_unmap_aux_granules;
	}

	if (!complete_mmio_emulation(rec, &rec_run.enter)) {
		ret = RMI_ERROR_REC;
		goto out_unmap_aux_granules;
	}

	if (!complete_host_call(rec, &rec_run)) {
		ret = RMI_SUCCESS;
		goto out_unmap_aux_granules;
	}

	/* If active plane is not P0 ... */
	if (!rec_is_plane_0_active(rec)) {
		bool report_err = false;

		sysregs = rec_active_plane_sysregs(rec);

		/*
		 * ... and either REC_ENTRY_FLAG_FORCE_P0 or
		 * REC_ENTRY_FLAG_INJECT_SEA are set, then exit the plane
		 * with sync exception and go back to P0. Else...
		 */
		if (((rec_run.enter.flags &
			(REC_ENTRY_FLAG_FORCE_P0 | REC_ENTRY_FLAG_INJECT_SEA)) != 0UL)) {
			report_err = !handle_plane_n_exit(rec, &rec_run.exit,
						ARM_EXCEPTION_SYNC_LEL, false);
		/*
		 * ... if the active plane is not the current GIC owner and there
		 * is a pending interrupt, then exit the plane with IRQ exception
		 * and go back to P0.
		 *
		 * Note, in both cases, that we do not need to save PN context
		 * back to the REC, as it was already saved when RMM first
		 * received the interrupt and exited to NS.
		 */
		} else if ((rec->active_plane_id != rec->gic_owner) &&
			   (gic_is_interrupt_pending(&rec_run.enter.gicv3_lrs[0]) ||
			   gic_is_maint_interrupt_pending(&sysregs->gicstate))) {
			report_err = !handle_plane_n_exit(rec, &rec_run.exit,
						ARM_EXCEPTION_IRQ_LEL, false);
		}

		if (report_err) {
			ret = RMI_ERROR_INPUT;
			goto out_unmap_aux_granules;
		}
	}

	/*
	 * Active plane might have changed due to conditions listed above and
	 * Pn exit to P0.
	 */
	plane = rec_active_plane(rec);
	sysregs = rec_active_plane_sysregs(rec);

	if (rec->active_plane_id == rec->gic_owner) {
		gic_copy_state_from_entry(&sysregs->gicstate,
				(unsigned long *)&rec_run.enter.gicv3_lrs,
				rec_run.enter.gicv3_hcr);
	}

	rec->set_ripas.response =
		((rec_run.enter.flags & REC_ENTRY_FLAG_RIPAS_RESPONSE) == 0UL) ?
			ACCEPT : REJECT;
	complete_set_ripas(rec);

	/* Complete REC exit due to DEV_MEM_MAP */
	complete_dev_mem_mapping(rec, &rec_run.enter);

	rec->set_s2ap.response =
		((rec_run.enter.flags & REC_ENTRY_FLAG_S2AP_RESPONSE) == 0UL) ?
			ACCEPT : REJECT;
	complete_set_s2ap(rec);

	complete_sysreg_emulation(rec, &rec_run.enter);

	if (rec->vdev.is_comm) {
		handle_rsi_rdev_complete(rec);
	}

	reset_last_run_info(plane);

	sysregs->hcr_el2 = rec->common_sysregs.hcr_el2;
	if ((rec_run.enter.flags & REC_ENTRY_FLAG_TRAP_WFI) != 0UL) {
		sysregs->hcr_el2 |= HCR_TWI;
	}
	if ((rec_run.enter.flags & REC_ENTRY_FLAG_TRAP_WFE) != 0UL) {
		sysregs->hcr_el2 |= HCR_TWE;
	}

	ret = RMI_SUCCESS;

	/* ===== Phase 2 R2: Secure VM Pausing ===== */
        {
                static int vmi_paused = 0;
                static int r2_exit_count = 0;
                static int r2_done = 0;
                static int reject_count = 0;

                unsigned long pc_r2 = (unsigned long)sysregs->pp_sysregs.elr_el1;
                if (pc_r2 > 0xffff000000000000UL) {
                        r2_exit_count++;
                }

                /* 如果已暂停，拒绝执行 Realm VM */
                if (vmi_paused) {
                        reject_count++;
                        if (reject_count <= 3) {
                                ERROR(">>> R2: REC_ENTER rejected #%d (VM paused) <<<\n",
                                        reject_count);
                        }
                        /* 拒绝 50 次后做分析并恢复 */
                        if (reject_count == 50) {
                                ERROR(">>> R2: Rejected %d REC_ENTER calls <<<\n",
                                        reject_count);
				ERROR(">>> R2: VM was frozen, now RESUMING <<<\n");
                                vmi_paused = 0;
                                r2_done = 1;
                        }
                        /* 不调用 rec_run_loop，直接返回 */
                        rec_run.exit.exit_reason = RMI_EXIT_HOST_CALL;
                        goto out_unmap_aux_granules;
                }

                /* 在 exit #5000 触发暂停 */
                if (r2_exit_count == 99999999 && !r2_done) {
                        vmi_paused = 1;
                        ERROR(">>> R2: PAUSING Realm VM at exit #%d <<<\n",
                                r2_exit_count);
                        rec_run.exit.exit_reason = RMI_EXIT_HOST_CALL;
                        goto out_unmap_aux_granules;
                }
        }

	/* ===== VMI R3: Set page write trap ===== */
        {
                if (!r3_trap_setup_done && !vmi_trap_fired) {
                        static int r3_wait = 0;
                        unsigned long pc_r3 = (unsigned long)sysregs->pp_sysregs.elr_el1;

                        if (pc_r3 > 0xffff000000000000UL) {
                                r3_wait++;
                        }

                        /* Wait until kernel is booted (after R1d finishes) */
                        if (r3_wait == 99999999) {
                                unsigned long test_ipa = 0x8034c000UL;
                                struct rd *rd_vmi;
                                struct s2tt_context *s2_ctx;
                                struct s2tt_walk wi;
                                unsigned long *s2tt;
                                unsigned long s2tte;

                                rd_vmi = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
                                if (rd_vmi != NULL) {
                                        s2_ctx = &rd_vmi->s2_ctx[PRIMARY_S2_CTX_ID];
                                        granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
                                        s2tt_walk_lock_unlock(s2_ctx, test_ipa,
                                                              S2TT_PAGE_LEVEL, &wi);

                                        s2tt = buffer_granule_mecid_map(wi.g_llt,
                                                SLOT_RTT, s2_ctx->mecid);
                                        if (s2tt != NULL) {
                                                s2tte = s2tte_read(&s2tt[wi.index]);
                                                ERROR(">>> R3: Original s2tte=0x%lx at IPA=0x%lx level=%ld idx=%lu <<<\n",
                                                        s2tte, test_ipa, wi.last_level, wi.index);

                                                if (s2tte_is_assigned_ram(s2_ctx, s2tte, wi.last_level)) {
                                                        r3_original_s2tte = s2tte;

							/* Direct bit manipulation:
                                                	 * bit 6 = R, bit 7 = W
                                                 	* Clear W bit to make page read-only
                                                 	*/
                                                	s2tte = s2tte & ~(1UL << 7);
                                                        
							s2tte_write(&s2tt[wi.index], s2tte);
                                                        s2tt_invalidate_page(s2_ctx, test_ipa);

                                                        vmi_trap_ipa = test_ipa;
                                                        vmi_trap_enabled = true;
                                                        r3_trap_setup_done = true;

                                                        ERROR(">>> R3: TRAP SET! new s2tte=0x%lx IPA=0x%lx <<<\n",
                                                                s2tte, test_ipa);
                                                } else {
                                                        ERROR(">>> R3: IPA 0x%lx not assigned RAM, skip <<<\n",
                                                                test_ipa);
                                                }
                                                buffer_unmap(s2tt);
                                        }
                                        granule_unlock(wi.g_llt);
                                        buffer_unmap(rd_vmi);
                                }
                        }
                }

                /* Restore permission after trap fired (Option C) */
                if (r3_restore_pending) {
                        struct rd *rd_vmi;
                        struct s2tt_context *s2_ctx;
                        struct s2tt_walk wi;
                        unsigned long *s2tt;

                        rd_vmi = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
                        if (rd_vmi != NULL) {
                                s2_ctx = &rd_vmi->s2_ctx[PRIMARY_S2_CTX_ID];
                                granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
                                s2tt_walk_lock_unlock(s2_ctx, vmi_trap_ipa,
                                                      S2TT_PAGE_LEVEL, &wi);
                                s2tt = buffer_granule_mecid_map(wi.g_llt,
                                        SLOT_RTT, s2_ctx->mecid);
                                if (s2tt != NULL) {
                                        /* Restore original s2tte */
                                        s2tte_write(&s2tt[wi.index], r3_original_s2tte);
                                        s2tt_invalidate_page(s2_ctx, vmi_trap_ipa);
                                        ERROR(">>> R3: Permission RESTORED for IPA=0x%lx <<<\n",
                                                vmi_trap_ipa);
                                        buffer_unmap(s2tt);
                                }
                                granule_unlock(wi.g_llt);
                                buffer_unmap(rd_vmi);
                        }
                        r3_restore_pending = false;
                }
        }
        /* ===== VMI R3 end ===== */

	rec_run_loop(rec, &rec_run.exit);

	/* ===== VMI R3: Post-trap analysis ===== */
        if (vmi_trap_fired) {
                ERROR(">>> R3: === TRAP ANALYSIS START === <<<\n");
                ERROR(">>> R3: Monitored page 0x%lx was WRITTEN by Realm VM <<<\n",
                        vmi_trap_ipa);
                ERROR(">>> R3: exit_reason=0x%lx <<<\n",
                        (unsigned long)rec_run.exit.exit_reason);

                /* Read current registers at trap point */
                {
                        unsigned long trap_pc = (unsigned long)sysregs->pp_sysregs.elr_el1;
                        unsigned long trap_sp = (unsigned long)sysregs->pp_sysregs.sp_el1;
                        unsigned long trap_task = sysregs->pp_sysregs.sp_el0;
                        ERROR(">>> R3: PC=0x%lx SP=0x%lx current_task=0x%lx <<<\n",
                                trap_pc, trap_sp, trap_task);
                }

                /* Use R1d to list processes at trap point */
                {
                        unsigned long ttbr1_val = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
                        unsigned long task_va = sysregs->pp_sysregs.sp_el0;
                        unsigned long pa_result, ret, val;
                        unsigned long tasks_off = 0x400UL;
                        unsigned long pid_off   = 0x4D0UL;
                        unsigned long comm_off  = 0x6B8UL;
                        unsigned long task;
			int count;

                        ret = vmi_va_to_pa(rec, task_va, ttbr1_val, &pa_result);
                        if (ret == 0UL) {
                                task = task_va;
                                ERROR(">>> R3: Process list at trap point: <<<\n");
                                for (count = 0; count < 200; count++) {
                                        unsigned long c1 = 0, c2 = 0;
                                        int pid_val = 0;

                                        ret = vmi_va_to_pa(rec, task + comm_off, ttbr1_val, &pa_result);
                                        if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c1); }
                                        ret = vmi_va_to_pa(rec, task + comm_off + 8, ttbr1_val, &pa_result);
                                        if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c2); }

                                        ret = vmi_va_to_pa(rec, task + pid_off, ttbr1_val, &pa_result);
                                        if (ret == 0UL) {
                                                vmi_read_pa(rec, pa_result, &val);
                                                pid_val = (int)(val & 0xFFFFFFFF);
                                        }

                                        ERROR(">>> R3: PROC[%d] pid=%d comm=%.8s%.8s <<<\n",
                                                count, pid_val, (char*)&c1, (char*)&c2);

                                        unsigned long next_tasks;
                                        ret = vmi_va_to_pa(rec, task + tasks_off, ttbr1_val, &pa_result);
                                        if (ret == 0UL) {
                                                vmi_read_pa(rec, pa_result, &next_tasks);
                                                unsigned long next_task = next_tasks - tasks_off;
                                                if (next_task == task_va || count >= 49) {
                                                        ERROR(">>> R3: === Total: %d processes === <<<\n",
                                                                count + 1);
                                                        break;
                                                }
                                                task = next_task;
                                        } else {
                                                break;
                                        }
                                }
                        } else {
                                ERROR(">>> R3: Cannot translate task VA, skip process list <<<\n");
                        }
                }

                ERROR(">>> R3: === TRAP ANALYSIS DONE === <<<\n");
                r3_restore_pending = true;
                vmi_trap_fired = false;
        }
        /* ===== VMI R3 end ===== */

	/* Active plane might have changed during rec_run_loop() */
	sysregs = rec_active_plane_sysregs(rec);

	/* ===== Phase 1 VMI: Read Realm VM registers ===== */
	{
		static int vmi_count = 0;
		unsigned long ttbr0 = (unsigned long)sysregs->pp_sysregs.ttbr0_el1.lo;
		unsigned long pc = (unsigned long)sysregs->pp_sysregs.elr_el1;
		if (pc > 0xffff000000000000UL && vmi_count < 5) {	
			ERROR(">>> VMI[%d] Realm VM regs after exit <<<\n", vmi_count);
			ERROR(">>>   TTBR0_EL1 = 0x%lx\n", ttbr0);
			ERROR(">>>   TTBR1_EL1 = 0x%lx\n",
				(unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo);
			ERROR(">>>   ELR_EL1(PC) = 0x%lx\n",
				(unsigned long)sysregs->pp_sysregs.elr_el1);
			ERROR(">>>   SP_EL1 = 0x%lx\n",
				(unsigned long)sysregs->pp_sysregs.sp_el1);
			ERROR(">>>   SCTLR_EL1 = 0x%lx\n",
				(unsigned long)sysregs->pp_sysregs.sctlr_el1);
			ERROR(">>>   TCR_EL1 = 0x%lx\n",
				(unsigned long)sysregs->pp_sysregs.tcr_el1);
			ERROR(">>>   ESR_EL1 = 0x%lx\n",
				(unsigned long)sysregs->pp_sysregs.esr_el1);
			ERROR(">>>   exit_reason = 0x%lx\n",
				(unsigned long)rec_run.exit.exit_reason);
			vmi_count++;
		}
	}

	/* ===== Phase 1 L2: Read Realm VM physical memory ===== */
	{
		static int l2_count = 0;
		unsigned long ttbr1_pa = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
		unsigned long pc2 = (unsigned long)sysregs->pp_sysregs.elr_el1;	
		if (pc2 > 0xffff000000000000UL && l2_count < 3) {
			struct s2_walk_result walk_res;
			enum s2_walk_status ws;

			ws = realm_ipa_to_pa(rec, ttbr1_pa & GRANULE_MASK, &walk_res);
			if (ws == WALK_SUCCESS) {
				struct granule *gr = find_granule(walk_res.pa);
				unsigned long *page_ptr;

				page_ptr = (unsigned long *)buffer_granule_mecid_map(
					gr, SLOT_REALM,
					rec->realm_info.primary_s2_ctx.mecid);

				if (page_ptr != NULL) {
					int i;
					int found = 0;
					ERROR(">>> L2[%d] Kernel L0 PT at IPA=0x%lx PA=0x%lx <<<\n",
						l2_count, ttbr1_pa, walk_res.pa);
					for (i = 0; i < 512; i++) {
						if (page_ptr[i] != 0UL) {
							ERROR(">>>   entry[%d] = 0x%lx\n", i, page_ptr[i]);
							found++;
							if (found >= 8) break;
						}
					}
					if (found == 0) {
						ERROR(">>>   ALL ENTRIES ARE ZERO\n");
					}
					buffer_unmap(page_ptr);
				}
				granule_unlock(walk_res.llt);
			} else {
				ERROR(">>> L2[%d] RTT walk failed for IPA=0x%lx status=%d <<<\n",
					l2_count, ttbr1_pa, (int)ws);
			}
			l2_count++;
		}
	}
	
	/* ===== Phase 1 L3: Virtual address translation + read kernel data ===== */
	{
		static int l3_count = 0;
		unsigned long pc3 = (unsigned long)sysregs->pp_sysregs.elr_el1;
		unsigned long ttbr1_val = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;

		if (pc3 > 0xffff000000000000UL && l3_count < 3) {
			unsigned long pa_result;
			unsigned long ret;

			/* Test 1: Translate the PC itself */
			ret = vmi_va_to_pa(rec, pc3, ttbr1_val, &pa_result);
			ERROR(">>> L3[%d] VA translation test <<<\n", l3_count);
			ERROR(">>>   PC VA = 0x%lx -> PA = 0x%lx (ret=%ld)\n",
				pc3, pa_result, ret);

			/* Test 2: Translate SP */
			{
				unsigned long sp = (unsigned long)sysregs->pp_sysregs.sp_el1;
				ret = vmi_va_to_pa(rec, sp, ttbr1_val, &pa_result);
				ERROR(">>>   SP VA = 0x%lx -> PA = 0x%lx (ret=%ld)\n",
					sp, pa_result, ret);
			}

			/* Test 3: If PC translation succeeded, read instruction at PC */
			ret = vmi_va_to_pa(rec, pc3, ttbr1_val, &pa_result);
			if (ret == 0UL) {
				unsigned long instr_val;
				unsigned long rr = vmi_read_pa(rec, pa_result, &instr_val);
				if (rr == 0UL) {
					ERROR(">>>   Instruction at PC = 0x%lx\n", instr_val);
				}
			}

			l3_count++;
		}
	}

	/* ===== Phase 1 R1d: Find task_struct offsets and list processes ===== */
	{
		static int r1d_count = 0;
		static int exit_count_r1d = 0;
		unsigned long pc4 = (unsigned long)sysregs->pp_sysregs.elr_el1;
		unsigned long ttbr1_val = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;

		if (pc4 > 0xffff000000000000UL) {
			exit_count_r1d++;
		}

		/* Wait for many exits to ensure kernel is fully booted */
		if (exit_count_r1d == 100000 && r1d_count < 1) {
			unsigned long pa_result;
			unsigned long ret;
			unsigned long val;

			unsigned long current_task = sysregs->pp_sysregs.sp_el0;
			ERROR(">>> R1d[%d] exit#%d current_task(SP_EL0)=0x%lx PC=0x%lx <<<\n",
				r1d_count, exit_count_r1d, current_task, pc4);

			/* Dump L0 entries to see what's mapped */
			{
				unsigned long l0_ipa = ttbr1_val & 0x0000FFFFFFFFF000UL;
				int i;
				ERROR(">>>   TTBR1 -> L-1 table at IPA=0x%lx\n", l0_ipa);
				for (i = 0; i < 16; i++) {
					unsigned long entry;
					unsigned long rr = vmi_read_pa(rec, l0_ipa + i * 8, &entry);
					if (rr == 0UL) {
						ERROR(">>>   L-1[%d] = 0x%lx\n", i, entry);
					}
				}
			}

			/* Translate current_task */
			ret = vmi_va_to_pa(rec, current_task, ttbr1_val, &pa_result);
			ERROR(">>>   current_task translate ret=%ld pa=0x%lx\n",
				(long)ret, pa_result);
	
			if (ret == 0UL) {
				unsigned long tasks_off = 0x400UL;
				unsigned long pid_off   = 0x4D0UL;
				unsigned long comm_off  = 0x6B8UL;

				/* Walk process list */
				unsigned long task = current_task;
				int count;
				for (count = 0; count < 200; count++) {
					/* Read comm (16 bytes) */
					unsigned long c1 = 0, c2 = 0;
					ret = vmi_va_to_pa(rec, task + comm_off, ttbr1_val, &pa_result);
					if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c1); }
					ret = vmi_va_to_pa(rec, task + comm_off + 8, ttbr1_val, &pa_result);
					if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c2); }

					/* Read pid */
					int pid_val = 0;
					ret = vmi_va_to_pa(rec, task + pid_off, ttbr1_val, &pa_result);
					if (ret == 0UL) {
						vmi_read_pa(rec, pa_result, &val);
						pid_val = (int)(val & 0xFFFFFFFF);
					}

					ERROR(">>>   PROC[%d] pid=%d comm=%.8s%.8s\n",
						count, pid_val, (char*)&c1, (char*)&c2);

					/* Read tasks.next */
					unsigned long next_tasks;
					ret = vmi_va_to_pa(rec, task + tasks_off, ttbr1_val, &pa_result);
					if (ret == 0UL) {
						vmi_read_pa(rec, pa_result, &next_tasks);
						unsigned long next_task = next_tasks - tasks_off;
						if (next_task == current_task || count >= 49) {
							ERROR(">>>   === Total: %d processes ===\n", count + 1);
							break;
						}
						task = next_task;
					} else {
						ERROR(">>>   (failed at task 0x%lx)\n", task);
						break;
					}
				}
			}

			r1d_count++;
		}
	}

	/* ===== RMI-triggered VMI scan simulation at exit 200000 ===== */
        {
                static int scan_done = 0;
                static int exit_count_scan = 0;
                unsigned long pc_scan = (unsigned long)sysregs->pp_sysregs.elr_el1;
                if (pc_scan > 0xffff000000000000UL) {
                        exit_count_scan++;
                }
                if (exit_count_scan == 200000 && scan_done < 1) {
                        unsigned long ttbr1_val = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
                        unsigned long current_task = sysregs->pp_sysregs.sp_el0;
                        unsigned long tasks_off = 0x400UL;
                        unsigned long pid_off = 0x4D0UL;
                        unsigned long comm_off = 0x6B8UL;
                        unsigned long pa_result, val, ret;
                        ERROR(">>> VMI_SCAN[RMI]: current_task=0x%lx ttbr1=0x%lx <<<\n",
                                current_task, ttbr1_val);
                        ret = vmi_va_to_pa(rec, current_task, ttbr1_val, &pa_result);
                        if (ret == 0UL) {
                                unsigned long task = current_task;
                                int count;
                                for (count = 0; count < 200; count++) {
                                        unsigned long c1 = 0, c2 = 0;
                                        ret = vmi_va_to_pa(rec, task + comm_off, ttbr1_val, &pa_result);
                                        if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c1); }
                                        ret = vmi_va_to_pa(rec, task + comm_off + 8, ttbr1_val, &pa_result);
                                        if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c2); }
                                        int pid_val = 0;
                                        ret = vmi_va_to_pa(rec, task + pid_off, ttbr1_val, &pa_result);
                                        if (ret == 0UL) {
                                                vmi_read_pa(rec, pa_result, &val);
                                                pid_val = (int)(val & 0xFFFFFFFF);
                                        }
                                        ERROR(">>> VMI_SCAN PROC[%d] pid=%d comm=%.8s%.8s <<<\n",
                                                count, pid_val, (char*)&c1, (char*)&c2);
                                        unsigned long next_tasks;
                                        ret = vmi_va_to_pa(rec, task + tasks_off, ttbr1_val, &pa_result);
                                        if (ret == 0UL) {
                                                vmi_read_pa(rec, pa_result, &next_tasks);
                                                unsigned long next_task = next_tasks - tasks_off;
                                                if (next_task == current_task || count >= 49) {
                                                        ERROR(">>> VMI_SCAN: === Total: %d processes === <<<\n", count + 1);
                                                        break;
                                                }
                                                task = next_task;
                                        } else {
                                                break;
                                        }
                                }
                        }
                        scan_done++;
                }
        }

	if (rec->active_plane_id == rec->gic_owner) {
		gic_copy_state_to_exit(&sysregs->gicstate,
					   (unsigned long *)&rec_run.exit.gicv3_lrs,
					   &rec_run.exit.gicv3_hcr,
					   &rec_run.exit.gicv3_misr,
					   &rec_run.exit.gicv3_vmcr);
	}

out_unmap_aux_granules:
	/* Unmap auxiliary granules */
	buffer_rec_aux_unmap(rec_aux, rec->num_rec_aux);

out_unmap_buffers:
	buffer_unmap(rec);
	ERROR(">>> RMM exit: ret=%lu, exit.gprs[0]=0x%lx <<<\n",
              ret, rec_run.exit.gprs[0]);
	if (ret == RMI_SUCCESS) {
		bool wrote = ns_buffer_write(
                        SLOT_NS, g_run,
                        (unsigned int)offsetof(struct rmi_rec_run, exit),
                        sizeof(struct rmi_rec_exit), &rec_run.exit);
                ERROR(">>> RMM ns_buffer_write returned %d <<<\n", (int)wrote);
                if (!wrote) {
                        ret = RMI_ERROR_INPUT;
                }
	}

	atomic_granule_put_release(g_rec);

	return ret;
}

static void smc_vmi_cmd(unsigned long rec_addr, unsigned long run_addr,
                         unsigned long cmd, unsigned long arg0,
                         struct smc_result *res);

/* ===== VMI: RMI-triggered process scan ===== */
void smc_vmi_scan_procs(unsigned long rec_addr,
                        unsigned long run_addr,
                        unsigned long cmd,
                        unsigned long arg0,
                        struct smc_result *res)
{
    (void)run_addr;

    /* If cmd > 0, dispatch to fine-grained VMI handler */
    if (cmd > 0) {
        smc_vmi_cmd(rec_addr, run_addr, cmd, arg0, res);
        return;
    }

    /* cmd == 0: original full scan logic follows */

    struct granule *g_rec;
    struct rec *rec;
    unsigned long ret;
    
    /* Reuse existing rec lookup logic from smc_rec_enter */
    g_rec = find_lock_granule(rec_addr, GRANULE_STATE_REC);
    if (g_rec == NULL) {
        res->x[0] = RMI_ERROR_INPUT; return;
    }
    rec = buffer_granule_map(g_rec, SLOT_REC);
    if (rec == NULL) {
        granule_unlock(g_rec);
    	res->x[0] = RMI_ERROR_REC; return;
    }

    /* Get sysregs for TTBR1 and SP_EL0 */
    struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
    unsigned long ttbr1_val = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
    unsigned long current_task = sysregs->pp_sysregs.sp_el0;
    unsigned long tasks_off = 0x400UL;
    unsigned long pid_off = 0x4D0UL;
    unsigned long comm_off = 0x6B8UL;
    unsigned long pa_result, val;
    
    ERROR(">>> VMI_SCAN: current_task=0x%lx ttbr1=0x%lx <<<\n",
          current_task, ttbr1_val);

    ret = vmi_va_to_pa(rec, current_task, ttbr1_val, &pa_result);
    if (ret != 0UL) {
        ERROR(">>> VMI_SCAN: VA translate failed ret=%lu <<<\n", ret);
        buffer_unmap(rec);
        granule_unlock(g_rec);
    	res->x[0] = RMI_ERROR_REC; return;
    }

    unsigned long task = current_task;
    int count;
    for (count = 0; count < 200; count++) {
        unsigned long c1 = 0, c2 = 0;
        ret = vmi_va_to_pa(rec, task + comm_off, ttbr1_val, &pa_result);
        if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c1); }
        ret = vmi_va_to_pa(rec, task + comm_off + 8, ttbr1_val, &pa_result);
        if (ret == 0UL) { vmi_read_pa(rec, pa_result, &c2); }

        int pid_val = 0;
        ret = vmi_va_to_pa(rec, task + pid_off, ttbr1_val, &pa_result);
        if (ret == 0UL) {
            vmi_read_pa(rec, pa_result, &val);
            pid_val = (int)(val & 0xFFFFFFFF);
        }

        ERROR(">>> VMI_SCAN PROC[%d] pid=%d comm=%.8s%.8s <<<\n",
              count, pid_val, (char*)&c1, (char*)&c2);

        unsigned long next_tasks;
        ret = vmi_va_to_pa(rec, task + tasks_off, ttbr1_val, &pa_result);
        if (ret == 0UL) {
            vmi_read_pa(rec, pa_result, &next_tasks);
            unsigned long next_task = next_tasks - tasks_off;
            if (next_task == current_task) break;
            task = next_task;
        } else {
            break;
        }
    }

    ERROR(">>> VMI_SCAN: === Total: %d processes === <<<\n", count + 1);

    buffer_unmap(rec);
    granule_unlock(g_rec);
    res->x[0] = RMI_SUCCESS;
    return;
}
static void smc_vmi_cmd(unsigned long rec_addr, unsigned long run_addr,
                         unsigned long cmd, unsigned long arg0,
                         struct smc_result *res)
{
    (void)run_addr;
    struct granule *g_rec;
    struct rec *rec;
    unsigned long ret;
    unsigned long pa_result, val;

    g_rec = find_lock_granule(rec_addr, GRANULE_STATE_REC);
    if (g_rec == NULL) {
        res->x[0] = RMI_ERROR_INPUT;
        return;
    }

    rec = buffer_granule_map(g_rec, SLOT_REC);
    if (rec == NULL) {
        granule_unlock(g_rec);
        res->x[0] = RMI_ERROR_REC;
        return;
    }

    switch (cmd) {
    case 1: { /* READ_PA */
        ret = vmi_read_pa(rec, arg0, &val);
        if (ret == 0UL) {
            res->x[0] = RMI_SUCCESS;
            res->x[1] = val;
        } else {
            res->x[0] = RMI_ERROR_REC;
            res->x[1] = 0;
        }
        break;
    }
    case 2: { /* READ_VA */
        struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
        unsigned long ttbr1 = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo;
        ret = vmi_va_to_pa(rec, arg0, ttbr1, &pa_result);
        if (ret == 0UL) {
            ret = vmi_read_pa(rec, pa_result, &val);
        }
        if (ret == 0UL) {
            res->x[0] = RMI_SUCCESS;
            res->x[1] = val;
        } else {
            res->x[0] = RMI_ERROR_REC;
            res->x[1] = 0;
        }
        break;
    }
    case 3: { /* GET_VCPUREG */
        struct sysreg_state *sysregs = rec_active_plane_sysregs(rec);
        unsigned long reg_val = 0;
        switch (arg0) {
        case 0: reg_val = (unsigned long)sysregs->pp_sysregs.ttbr0_el1.lo; break;
	case 1: reg_val = (unsigned long)sysregs->pp_sysregs.ttbr1_el1.lo; break;
        case 2: reg_val = sysregs->pp_sysregs.sp_el0; break;
        case 3: reg_val = (unsigned long)sysregs->pp_sysregs.tcr_el1; break;
	case 4: reg_val = (unsigned long)sysregs->pp_sysregs.sctlr_el1; break;
        case 5: reg_val = (unsigned long)sysregs->pp_sysregs.vbar_el1; break;
        default: break;
        }
        res->x[0] = RMI_SUCCESS;
        res->x[1] = reg_val;
        break;
    }
    case 5: /* PAUSE_VM */
    case 6: /* RESUME_VM */
    case 7: /* SET_MEM_EVENT */
    case 8: /* CLR_MEM_EVENT */
        res->x[0] = RMI_SUCCESS;
        res->x[1] = 0;
        break;
    default:
        res->x[0] = RMI_ERROR_INPUT;
        res->x[1] = 0;
        break;
    }

    buffer_unmap(rec);
    granule_unlock(g_rec);
}
