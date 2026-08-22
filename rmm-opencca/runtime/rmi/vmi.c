/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 *
 * RealmEye VMI module: extracted from runtime/rmi/run.c.
 */

#include <arch.h>
#include <buffer.h>
#include <debug.h>
#include <granule.h>
#include <realm.h>
#include <rec.h>
#include <smc-rmi.h>
#include <vmi.h>

#ifdef CONFIG_RMM_VMI

#include <errno.h>
#include <mbedtls/gcm.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <memory_alloc.h>
#include <spinlock.h>
#include <string.h>

/*
 * Step 1: RMM-to-Host encryption only, single-session prototype.
 *
 * The receive/auth_decrypt path, anti-replay window, per-session key/salt
 * establishment and bidirectional support are TODO for step 2.
 *
 * Reusing this fixed PSK and salt across RMM reboots causes GCM nonce reuse
 * when sequence numbers restart. This prototype is NOT deployment-safe.
 */
#define VMI_CHANNEL_DIRECTION_RMM_TO_HOST	0U
#define VMI_CHANNEL_DIRECTION_HOST_TO_RMM	1U
#define VMI_GCM_NONCE_SIZE			12U
#define VMI_GCM_AAD_SIZE			10U
#define VMI_GCM_KEY_BITS			128U
#define VMI_CHANNEL_HEAP_SIZE			1024U
#define VMI_PERIODIC_MIN			1000UL
#define VMI_PERIODIC_MASK			0x7FFUL

/*
 * Fixed bring-up salt only. A deployment-safe implementation must establish
 * a fresh key or salt before sequence numbers restart.
 */
static const unsigned char vmi_session_salt[4] = {
	0x56U, 0x4dU, 0x49U, 0x01U
};

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

/*
 * Step-1 singleton channel state.
 *
 * mbedtls_gcm_context is mutable, so the same lock protects initialization
 * and every encryption operation. A later per-session implementation should
 * move this state into the corresponding Realm/channel object.
 */
static mbedtls_gcm_context vmi_gcm_ctx;
static bool vmi_gcm_ready;
static spinlock_t vmi_gcm_lock = { 0U };
static struct buffer_alloc_ctx vmi_gcm_heap_ctx;
static unsigned char vmi_gcm_heap[VMI_CHANNEL_HEAP_SIZE]
	__aligned(sizeof(unsigned long));
static unsigned long vmi_tx_sequence;
static bool vmi_periodic_enabled;
static unsigned long vmi_periodic_remaining;

static void vmi_put_u64_be(unsigned char *out, unsigned long value)
{
	unsigned int i;

	for (i = 0U; i < 8U; i++) {
		out[7U - i] = (unsigned char)(value >> (i * 8U));
	}
}

/*
 * Must be called with vmi_gcm_lock held.
 *
 * The configured Mbed TLS Cipher backend allocates an AES context from the
 * current PE's allocator during mbedtls_gcm_setkey(). Bind a dedicated VMI
 * heap while setting the key, then retain the allocated context for the
 * lifetime of this prototype channel.
 */
static int vmi_channel_init_locked(void)
{
	int ret;

	if (vmi_gcm_ready) {
		return 0;
	}

	ret = buffer_alloc_ctx_assign(&vmi_gcm_heap_ctx);
	if (ret != 0) {
		return ret;
	}

	mbedtls_memory_buffer_alloc_init(vmi_gcm_heap,
					sizeof(vmi_gcm_heap));
	mbedtls_gcm_init(&vmi_gcm_ctx);

	ret = mbedtls_gcm_setkey(&vmi_gcm_ctx, MBEDTLS_CIPHER_ID_AES,
				 vmi_psk, VMI_GCM_KEY_BITS);
	if (ret != 0) {
		mbedtls_gcm_free(&vmi_gcm_ctx);
		mbedtls_memory_buffer_alloc_free();
		buffer_alloc_ctx_unassign();
		return ret;
	}

	buffer_alloc_ctx_unassign();
	vmi_gcm_ready = true;
	return 0;
}

/*
 * Encrypt one fixed-size step-1 VMI record.
 *
 * nonce = session_salt[32] || sequence[64, big-endian]
 * AAD   = version[8] || direction[8] || sequence[64, big-endian]
 *
 * The caller supplies the sequence number. A later step will associate the
 * sequence state with an authenticated session and enforce replay rules.
 */
static int vmi_channel_encrypt(unsigned long sequence,
			       const unsigned char *plaintext,
			       size_t len,
			       struct vmi_aead_record *out_record)
{
	unsigned char nonce[VMI_GCM_NONCE_SIZE];
	unsigned char aad[VMI_GCM_AAD_SIZE];
	int ret;

	if ((plaintext == NULL) || (out_record == NULL) ||
	    (len != VMI_AEAD_PLAINTEXT_SIZE)) {
		return -EINVAL;
	}

	(void)memset(out_record, 0, sizeof(*out_record));

	(void)memcpy(nonce, vmi_session_salt, sizeof(vmi_session_salt));
	vmi_put_u64_be(&nonce[sizeof(vmi_session_salt)], sequence);

	aad[0] = VMI_AEAD_RECORD_VERSION;
	aad[1] = VMI_CHANNEL_DIRECTION_RMM_TO_HOST;
	vmi_put_u64_be(&aad[2], sequence);

	spinlock_acquire(&vmi_gcm_lock);

	ret = vmi_channel_init_locked();
	if (ret == 0) {
		ret = mbedtls_gcm_crypt_and_tag(
			&vmi_gcm_ctx, MBEDTLS_GCM_ENCRYPT, len,
			nonce, sizeof(nonce), aad, sizeof(aad),
			plaintext, out_record->ciphertext,
			sizeof(out_record->tag), out_record->tag);
	}

	spinlock_release(&vmi_gcm_lock);

	if (ret != 0) {
		(void)memset(out_record, 0, sizeof(*out_record));
		return ret;
	}

	out_record->sequence = sequence;
	return 0;
}

static void __unused vmi_encrypt_result(unsigned long proc_count, unsigned long status,
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
/* ===== VMI R3: Page write-trap state ===== */
bool vmi_trap_enabled;
static bool vmi_trap_fired;
unsigned long vmi_trap_ipa;
unsigned long vmi_trap_pa;
static unsigned long vmi_original_s2tte;
unsigned long vmi_last_fipa;
unsigned long vmi_hit_count;
unsigned long vmi_last_cycles;
unsigned long vmi_total_cycles;
unsigned long vmi_cnt_freq;
unsigned long vmi_setup_cycles;

static void vmi_log_guest_ctx(struct rec *rec, const char *tag)
{
	struct sysreg_state *sysregs = &rec->sysregs;

	ERROR(">>> VMI_CTX[%s]: rec_sp_el0=0x%lx sys_sp_el0=0x%lx ttbr1=0x%lx vbar=0x%lx <<<\n",
	      tag,
	      (unsigned long)rec->sp_el0,
	      sysregs->sp_el0,
	      sysregs->ttbr1_el1,
	      sysregs->vbar_el1);
}

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
	page_ptr = (unsigned long *)buffer_granule_map(gr, SLOT_RTT);
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
#if !VMI_PERF_MEASURE
	ERROR(">>> VMI VA2PA: ttbr=0x%lx L0 tbl=0x%lx idx=%lu entry=0x%lx <<<\n",
	      ttbr, table_ipa, l0_idx, entry);
#endif
	if (ret != 0UL || (entry & 0x3) != 0x3) {
		return 1UL;
	}

	/* L1 walk */
	table_ipa = entry & 0x0000FFFFFFFFF000UL;
	ret = vmi_read_pa(rec, table_ipa + l1_idx * 8, &entry);
#if !VMI_PERF_MEASURE
	ERROR(">>> VMI VA2PA: ttbr=0x%lx L1 tbl=0x%lx idx=%lu entry=0x%lx <<<\n",
	      ttbr, table_ipa, l1_idx, entry);
#endif
	if (ret != 0UL) {
		return 2UL;
	}
	/* Check for L1 block mapping (1GB) */
	if ((entry & 0x3) == 0x1) {
		*out_pa = (entry & 0x0000FFFFC0000000UL) | (va & 0x3FFFFFFFUL);
#if !VMI_PERF_MEASURE
		ERROR(">>> VMI VA2PA: va=0x%lx final_ipa=0x%lx (L1 block) <<<\n",
		      va, *out_pa);
#endif
		return 0UL;
	}
	if ((entry & 0x3) != 0x3) {
		return 2UL;
	}

	/* L2 walk */
	table_ipa = entry & 0x0000FFFFFFFFF000UL;
	ret = vmi_read_pa(rec, table_ipa + l2_idx * 8, &entry);
#if !VMI_PERF_MEASURE
	ERROR(">>> VMI VA2PA: ttbr=0x%lx L2 tbl=0x%lx idx=%lu entry=0x%lx <<<\n",
	      ttbr, table_ipa, l2_idx, entry);
#endif
	if (ret != 0UL) {
		return 3UL;
	}
	/* Check for L2 block mapping (2MB) */
	if ((entry & 0x3) == 0x1) {
		*out_pa = (entry & 0x0000FFFFFFE00000UL) | (va & 0x1FFFFFUL);
#if !VMI_PERF_MEASURE
		ERROR(">>> VMI VA2PA: va=0x%lx final_ipa=0x%lx (L2 block) <<<\n",
		      va, *out_pa);
#endif
		return 0UL;
	}
	if ((entry & 0x3) != 0x3) {
		return 3UL;
	}

	/* L3 walk */
	table_ipa = entry & 0x0000FFFFFFFFF000UL;
	ret = vmi_read_pa(rec, table_ipa + l3_idx * 8, &entry);
#if !VMI_PERF_MEASURE
	ERROR(">>> VMI VA2PA: ttbr=0x%lx L3 tbl=0x%lx idx=%lu entry=0x%lx <<<\n",
	      ttbr, table_ipa, l3_idx, entry);
#endif
	if (ret != 0UL) {
		return 4UL;
	}
	/* L3 entry: [1:0] must be 0b11 for valid page */
	if ((entry & 0x3) != 0x3) {
		return 4UL;
	}
	*out_pa = (entry & 0x0000FFFFFFFFF000UL) | (va & 0xFFFUL);
#if !VMI_PERF_MEASURE
	ERROR(">>> VMI VA2PA: va=0x%lx final_ipa=0x%lx (L3 page) <<<\n",
	      va, *out_pa);
#endif
	return 0UL;
}

/*
 * Install the R3 write trap by clearing the S2TTE write-permission bit.
 *
 * FVP used rd->s2_ctx[PRIMARY_S2_CTX_ID].  This tree has a single
 * struct s2tt_context in struct rd, so use rd->s2_ctx directly.
 */
static unsigned long vmi_setup_trap(struct rec *rec, unsigned long trap_ipa)
{
	struct rd *rd_vmi;
	struct s2tt_context *s2_ctx;
	struct s2tt_walk wi;
	unsigned long *s2tt;
	unsigned long s2tte;
	unsigned long ret = 1UL;
	unsigned long t0;
	unsigned long t1;

	if (vmi_trap_enabled) {
		return 3UL;
	}

	isb();
	t0 = read_cntpct_el0();

	trap_ipa &= GRANULE_MASK;
	rd_vmi = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	if (rd_vmi == NULL) {
		return ret;
	}

	s2_ctx = &rd_vmi->s2_ctx;
	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
	s2tt_walk_lock_unlock(s2_ctx, trap_ipa, S2TT_PAGE_LEVEL, &wi);
	/*
	 * FVP used buffer_granule_mecid_map(..., s2_ctx->mecid).  This
	 * real-RMM tree exposes neither that function nor s2_ctx->mecid;
	 * confirm that buffer_granule_map() is the intended platform API.
	 */
	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	if (s2tt != NULL) {
		s2tte = s2tte_read(&s2tt[wi.index]);
#if !VMI_PERF_MEASURE
		ERROR(">>> R3: Original s2tte=0x%lx at IPA=0x%lx level=%ld idx=%lu <<<\n",
		      s2tte, trap_ipa, wi.last_level, wi.index);
#endif

		if (wi.last_level != S2TT_PAGE_LEVEL) {
			ERROR(">>> R3: trap_ipa 0x%lx not at page level (last_level=%ld), skip to avoid corrupting block mapping <<<\n",
			      trap_ipa, wi.last_level);
			ret = 4UL;
		} else if (s2tte_is_assigned_ram(s2_ctx, s2tte,
						 wi.last_level)) {
			vmi_original_s2tte = s2tte;
			vmi_trap_pa = s2tte_pa(s2_ctx, vmi_original_s2tte,
					       wi.last_level);
			/* bit 6 = R, bit 7 = W; clear W to make it read-only. */
			s2tte &= ~(1UL << 7);
			s2tte_write(&s2tt[wi.index], s2tte);
			s2tt_invalidate_page(s2_ctx, trap_ipa);
			vmi_trap_ipa = trap_ipa;
			vmi_trap_enabled = true;
			vmi_trap_fired = false;
			ret = 0UL;
#if !VMI_PERF_MEASURE
			ERROR(">>> R3: TRAP SET! new s2tte=0x%lx IPA=0x%lx <<<\n",
			      s2tte, trap_ipa);
#endif
		} else {
			ERROR(">>> R3: IPA 0x%lx not assigned RAM, skip <<<\n",
			      trap_ipa);
			ret = 2UL;
		}
		buffer_unmap(s2tt);
	}

	granule_unlock(wi.g_llt);
	buffer_unmap(rd_vmi);
	if (ret == 0UL) {
		isb();
		t1 = read_cntpct_el0();
		vmi_setup_cycles = t1 - t0;
	}

	return ret;
}

unsigned long vmi_restore_trap(struct rec *rec)
{
	struct rd *rd_vmi;
	struct s2tt_context *s2_ctx;
	struct s2tt_walk wi;
	unsigned long *s2tt;
	unsigned long ret = 1UL;

	rd_vmi = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	if (rd_vmi == NULL) {
		return ret;
	}

	s2_ctx = &rd_vmi->s2_ctx;
	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
	s2tt_walk_lock_unlock(s2_ctx, vmi_trap_ipa, S2TT_PAGE_LEVEL, &wi);
	/* See the FVP/real-RMM mapping API note in vmi_setup_trap(). */
	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	if (s2tt != NULL) {
		s2tte_write(&s2tt[wi.index], vmi_original_s2tte);
		s2tt_invalidate_page(s2_ctx, vmi_trap_ipa);
#if !VMI_PERF_MEASURE
		ERROR(">>> R3: Permission RESTORED for IPA=0x%lx <<<\n",
		      vmi_trap_ipa);
#endif
		buffer_unmap(s2tt);
		ret = 0UL;
	}

	granule_unlock(wi.g_llt);
	buffer_unmap(rd_vmi);
	if (ret == 0UL) {
		vmi_trap_enabled = false;
		vmi_trap_fired = false;
	}
	return ret;
}

/* Analyze the monitored write-fault point. */
unsigned long vmi_handle_trap(struct rec *rec, unsigned long esr,
			      unsigned long hpfar)
{
#if !VMI_PERF_MEASURE
	struct sysreg_state *sysregs = &rec->sysregs;
#endif
	unsigned long fsc = esr & MASK(ESR_EL2_ABORT_FSC);
	unsigned long fipa = (hpfar & MASK(HPFAR_EL2_FIPA)) <<
			     HPFAR_EL2_FIPA_OFFSET;
#if VMI_PERF_MEASURE
	(void)rec;
#endif
#if 0
	unsigned long ttbr1_val = sysregs->ttbr1_el1;
	unsigned long task_va = sysregs->sp_el0;
	unsigned long pa_result, ret, val;
	unsigned long tasks_off = 0x400UL;
	unsigned long pid_off = 0x4D0UL;
	unsigned long comm_off = 0x6B8UL;
	unsigned long task;
	int count;
#endif

	if (!vmi_trap_enabled) {
		return 1UL;
	}
	if ((fsc < ESR_EL2_ABORT_FSC_PERMISSION_FAULT) ||
	    (fsc > (ESR_EL2_ABORT_FSC_PERMISSION_FAULT + 3UL)) ||
	    ((fipa & GRANULE_MASK) != vmi_trap_pa)) {
		ERROR(">>> R3: Not the monitored permission fault: ESR=0x%lx HPFAR=0x%lx <<<\n",
		      esr, hpfar);
		return 2UL;
	}

	vmi_last_fipa = fipa & GRANULE_MASK;
	vmi_hit_count += 1UL;
	vmi_trap_fired = true;
#if !VMI_PERF_MEASURE
	ERROR(">>> VMI R3: TRAP FIRED! fipa=0x%lx page=0x%lx <<<\n",
	      fipa, fipa & GRANULE_MASK);
	ERROR(">>> VMI R3: ESR=0x%lx HPFAR=0x%lx <<<\n",
	      esr, hpfar);
	ERROR(">>> R3: === TRAP ANALYSIS START === <<<\n");
	ERROR(">>> R3: Monitored page 0x%lx was WRITTEN by Realm VM <<<\n",
	      vmi_trap_ipa);
	ERROR(">>> R3: PC=0x%lx SP=0x%lx current_task=0x%lx <<<\n",
	      sysregs->elr_el1, sysregs->sp_el1, sysregs->sp_el0);
#endif

#if 0
	ret = vmi_va_to_pa(rec, task_va, ttbr1_val, &pa_result);
	if (ret == 0UL) {
		task = task_va;
		ERROR(">>> R3: Process list at trap point: <<<\n");
		for (count = 0; count < 200; count++) {
			unsigned long c1 = 0UL, c2 = 0UL, next_tasks;
			unsigned long next_task;
			int pid_val = 0;

			ret = vmi_va_to_pa(rec, task + comm_off, ttbr1_val,
					       &pa_result);
			if (ret == 0UL) {
				(void)vmi_read_pa(rec, pa_result, &c1);
			}
			ret = vmi_va_to_pa(rec, task + comm_off + 8UL,
					       ttbr1_val, &pa_result);
			if (ret == 0UL) {
				(void)vmi_read_pa(rec, pa_result, &c2);
			}
			ret = vmi_va_to_pa(rec, task + pid_off, ttbr1_val,
					       &pa_result);
			if (ret == 0UL) {
				(void)vmi_read_pa(rec, pa_result, &val);
				pid_val = (int)(val & 0xFFFFFFFFUL);
			}
			ERROR(">>> R3: PROC[%d] pid=%d comm=%.8s%.8s <<<\n",
			      count, pid_val, (char *)&c1, (char *)&c2);

			ret = vmi_va_to_pa(rec, task + tasks_off, ttbr1_val,
					       &pa_result);
			if (ret != 0UL) {
				break;
			}
			(void)vmi_read_pa(rec, pa_result, &next_tasks);
			next_task = next_tasks - tasks_off;
			if ((next_task == task_va) || (count >= 49)) {
				ERROR(">>> R3: === Total: %d processes === <<<\n",
				      count + 1);
				break;
			}
			task = next_task;
		}
	} else {
		ERROR(">>> R3: Cannot translate task VA, skip process list <<<\n");
	}
#endif

#if !VMI_PERF_MEASURE
	ERROR(">>> R3: === TRAP ANALYSIS DONE === <<<\n");
#endif
	return 0UL;
}


static inline unsigned long perf_cycles(void)
{
    unsigned long v;
    asm volatile("isb; mrs %0, cntpct_el0" : "=r"(v));
    return v;
}
#ifdef CONFIG_VMI_PERF_EVAL
#define VMI_PERF_WARMUP	10U
#define VMI_PERF_SAMPLES	1000U

static unsigned long vmi_perf_samples[VMI_PERF_SAMPLES];
static spinlock_t vmi_perf_lock = { 0U };

static void vmi_perf_sort(unsigned long *s, unsigned int n)
{
	unsigned int start;
	unsigned int end;

	if (n < 2U) {
		return;
	}

	/* Build a max heap, then move its root to the end repeatedly. */
	start = n / 2U;
	while (start > 0U) {
		unsigned int root;

		start--;
		root = start;
		while ((root * 2U) + 1U < n) {
			unsigned int child = (root * 2U) + 1U;
			unsigned long tmp;

			if ((child + 1U < n) && (s[child] < s[child + 1U])) {
				child++;
			}
			if (s[root] >= s[child]) {
				break;
			}
			tmp = s[root];
			s[root] = s[child];
			s[child] = tmp;
			root = child;
		}
	}

	end = n - 1U;
	while (end > 0U) {
		unsigned long tmp = s[0];
		unsigned int root = 0U;

		s[0] = s[end];
		s[end] = tmp;
		while ((root * 2U) + 1U < end) {
			unsigned int child = (root * 2U) + 1U;

			if ((child + 1U < end) &&
			    (s[child] < s[child + 1U])) {
				child++;
			}
			if (s[root] >= s[child]) {
				break;
			}
			tmp = s[root];
			s[root] = s[child];
			s[child] = tmp;
			root = child;
		}
		end--;
	}
}

static unsigned long vmi_perf_median_range(const unsigned long *s,
					   unsigned int first,
					   unsigned int count)
{
	unsigned int lo = first + ((count - 1U) / 2U);
	unsigned int hi = first + (count / 2U);
	unsigned long a = s[lo];
	unsigned long b = s[hi];

	return a + ((b - a) / 2UL);
}

/* Called with vmi_perf_lock held; releases it before writing to the UART. */
static void vmi_perf_print_summary(const char *name, unsigned long *s,
				   unsigned int n, unsigned int failures)
{
	unsigned long min = 0UL;
	unsigned long p25 = 0UL;
	unsigned long median = 0UL;
	unsigned long p75 = 0UL;
	unsigned long max = 0UL;

	if (n != 0U) {
		unsigned int p25_lo;
		unsigned int p25_hi;
		unsigned int p75_lo;
		unsigned int p75_hi;

		vmi_perf_sort(s, n);
		min = s[0];
		p25_lo = (n - 1U) / 4U;
		p25_hi = n / 4U;
		p25 = s[p25_lo] + ((s[p25_hi] - s[p25_lo]) / 2UL);
		median = vmi_perf_median_range(s, 0U, n);
		p75_lo = (3U * (n - 1U)) / 4U;
		p75_hi = (3U * n) / 4U;
		p75 = s[p75_lo] + ((s[p75_hi] - s[p75_lo]) / 2UL);
		max = s[n - 1U];
	}

	spinlock_release(&vmi_perf_lock);
	ERROR("PERF_SUMMARY,%s,n=%u,fail=%u,min=%lu,p25=%lu,median=%lu,"
	      "p75=%lu,max=%lu\n",
	      name, n, failures, min, p25, median, p75, max);
}

static void perf_test_aes(void)
{
    unsigned char in[16], out[16];
    unsigned char round_keys[176];
    unsigned long t1, t2;
    unsigned int i;

    spinlock_acquire(&vmi_perf_lock);

    /* Init test data and keys (don't measure key expansion) */
    for (i = 0U; i < 16U; i++)
        in[i] = (unsigned char)i;
    vmi_aes_key_expansion(vmi_psk, round_keys);

    /* Run 1010 iterations: first 10 warmup (discarded), then 1000 measured */
    for (i = 0U; i < VMI_PERF_WARMUP + VMI_PERF_SAMPLES; i++) {
        t1 = perf_cycles();
        vmi_aes_encrypt_block(in, out, round_keys);
        t2 = perf_cycles();
        if (i >= VMI_PERF_WARMUP)
            vmi_perf_samples[i - VMI_PERF_WARMUP] = t2 - t1;
    }

    vmi_perf_print_summary("aes_encrypt_block", vmi_perf_samples,
                           VMI_PERF_SAMPLES, 0U);
}

/*
 * Strictly increasing receive replay state (single-session prototype).
 * There is deliberately no global instance yet; the real receive path will
 * add one when Host-to-RMM transport lands. Cmd 108 uses a local instance.
 */
struct vmi_rx_replay {
	unsigned long last_seq;
	bool valid;
};

#define VMI_RX_OK	0
#define VMI_RX_REPLAY	1

/*
 * Step-2 receive primitive. It is temporarily kept under
 * CONFIG_VMI_PERF_EVAL because cmd 107 is its only caller. Move it beside
 * vmi_channel_encrypt() once the real Host-to-RMM receive path uses it.
 */
static int vmi_channel_decrypt(unsigned char direction,
			       unsigned long sequence,
			       const struct vmi_aead_record *in,
			       unsigned char *out_plaintext,
			       size_t len)
{
	unsigned char nonce[VMI_GCM_NONCE_SIZE];
	unsigned char aad[VMI_GCM_AAD_SIZE];
	int ret;

	if ((in == NULL) || (out_plaintext == NULL) ||
	    (len != VMI_AEAD_PLAINTEXT_SIZE)) {
		return -EINVAL;
	}

	(void)memcpy(nonce, vmi_session_salt, sizeof(vmi_session_salt));
	vmi_put_u64_be(&nonce[sizeof(vmi_session_salt)], sequence);

	aad[0] = VMI_AEAD_RECORD_VERSION;
	aad[1] = direction;
	vmi_put_u64_be(&aad[2], sequence);

	spinlock_acquire(&vmi_gcm_lock);

	ret = vmi_channel_init_locked();
	if (ret == 0) {
		ret = mbedtls_gcm_auth_decrypt(
			&vmi_gcm_ctx, len,
			nonce, sizeof(nonce),
			aad, sizeof(aad),
			in->tag, sizeof(in->tag),
			in->ciphertext, out_plaintext);
	}

	spinlock_release(&vmi_gcm_lock);

	return ret;
}

/*
 * Step-2 authenticated receive primitive. It is temporarily kept under
 * CONFIG_VMI_PERF_EVAL with its diagnostic caller. Move it to the normal
 * receive path when Host-to-RMM transport lands.
 */
static int vmi_channel_receive(struct vmi_rx_replay *rx,
			       unsigned char direction,
			       const struct vmi_aead_record *in,
			       unsigned char *out_plaintext,
			       size_t len)
{
	int ret;

	if ((rx == NULL) || (in == NULL) || (out_plaintext == NULL) ||
	    (len != VMI_AEAD_PLAINTEXT_SIZE)) {
		return -EINVAL;
	}

	/*
	 * Authenticate first. An unauthenticated sequence number must never
	 * influence replay state.
	 */
	ret = vmi_channel_decrypt(direction, in->sequence, in,
				  out_plaintext, len);
	if (ret != 0) {
		return ret;
	}

	if (rx->valid && (in->sequence <= rx->last_seq)) {
		return VMI_RX_REPLAY;
	}

	rx->last_seq = in->sequence;
	rx->valid = true;
	return VMI_RX_OK;
}

/*
 * Test-only helper for creating a record with an explicitly selected
 * direction. It is kept under CONFIG_VMI_PERF_EVAL with cmd 107.
 */
static int vmi_diag_encrypt_dir(unsigned char direction,
				unsigned long sequence,
				const unsigned char *plaintext,
				size_t len,
				struct vmi_aead_record *out)
{
	unsigned char nonce[VMI_GCM_NONCE_SIZE];
	unsigned char aad[VMI_GCM_AAD_SIZE];
	int ret;

	if ((plaintext == NULL) || (out == NULL) ||
	    (len != VMI_AEAD_PLAINTEXT_SIZE)) {
		return -EINVAL;
	}

	(void)memset(out, 0, sizeof(*out));

	(void)memcpy(nonce, vmi_session_salt, sizeof(vmi_session_salt));
	vmi_put_u64_be(&nonce[sizeof(vmi_session_salt)], sequence);

	aad[0] = VMI_AEAD_RECORD_VERSION;
	aad[1] = direction;
	vmi_put_u64_be(&aad[2], sequence);

	spinlock_acquire(&vmi_gcm_lock);

	ret = vmi_channel_init_locked();
	if (ret == 0) {
		ret = mbedtls_gcm_crypt_and_tag(
			&vmi_gcm_ctx, MBEDTLS_GCM_ENCRYPT, len,
			nonce, sizeof(nonce),
			aad, sizeof(aad),
			plaintext, out->ciphertext,
			sizeof(out->tag), out->tag);
	}

	spinlock_release(&vmi_gcm_lock);

	if (ret != 0) {
		(void)memset(out, 0, sizeof(*out));
		return ret;
	}

	out->sequence = sequence;
	return 0;
}

static void perf_test_gcm(void)
{
	unsigned char plaintext[VMI_AEAD_PLAINTEXT_SIZE];
	unsigned char dec_out[VMI_AEAD_PLAINTEXT_SIZE];
	struct vmi_aead_record record;
	unsigned long sequence;
	unsigned long t1;
	unsigned long t2;
	unsigned int failures;
	unsigned int k;
	int ret;
	unsigned int i;

	spinlock_acquire(&vmi_perf_lock);

	for (i = 0U; i < sizeof(plaintext); i++) {
		plaintext[i] = (unsigned char)i;
	}

	/*
	 * Initialize before timing. The reported cycles measure the steady-state
	 * record encryption path, not first-use allocation and setkey.
	 */
	sequence = __atomic_fetch_add(&vmi_tx_sequence, 1UL,
				      __ATOMIC_RELAXED);
	ret = vmi_channel_encrypt(sequence, plaintext, sizeof(plaintext),
				  &record);
	if (ret != 0) {
		vmi_perf_print_summary("gcm_encrypt", vmi_perf_samples,
				       0U, 1U);
		return;
	}

	/*
	 * First 10 iterations are warmup; the following 1000 are measured.
	 * Every iteration consumes a distinct sequence number so the benchmark
	 * does not deliberately reuse a nonce within the current RMM boot.
	 */
	failures = 0U;
	k = 0U;
	for (i = 0U; i < VMI_PERF_WARMUP + VMI_PERF_SAMPLES; i++) {
		sequence = __atomic_fetch_add(&vmi_tx_sequence, 1UL,
					      __ATOMIC_RELAXED);
		t1 = perf_cycles();
		ret = vmi_channel_encrypt(sequence, plaintext,
					  sizeof(plaintext), &record);
		t2 = perf_cycles();

		if (i >= VMI_PERF_WARMUP) {
			if (ret == 0) {
				vmi_perf_samples[k++] = t2 - t1;
			} else {
				failures++;
			}
		}
	}
	vmi_perf_print_summary("gcm_encrypt", vmi_perf_samples, k,
			       failures);
	spinlock_acquire(&vmi_perf_lock);

	/*
	 * Produce one known-good RMM-to-Host record for steady-state
	 * authenticated decryption measurements.
	 */
	sequence = __atomic_fetch_add(&vmi_tx_sequence, 1UL,
				      __ATOMIC_RELAXED);
	ret = vmi_channel_encrypt(sequence, plaintext, sizeof(plaintext),
				  &record);
	if (ret != 0) {
		vmi_perf_print_summary("gcm_decrypt", vmi_perf_samples,
				       0U, 1U);
		return;
	}

	/* First 10 iterations are warmup; the following 1000 are measured. */
	failures = 0U;
	k = 0U;
	for (i = 0U; i < VMI_PERF_WARMUP + VMI_PERF_SAMPLES; i++) {
		t1 = perf_cycles();
		ret = vmi_channel_decrypt(
			VMI_CHANNEL_DIRECTION_RMM_TO_HOST,
			sequence, &record, dec_out, sizeof(dec_out));
		t2 = perf_cycles();

		if (i >= VMI_PERF_WARMUP) {
			if (ret == 0) {
				vmi_perf_samples[k++] = t2 - t1;
			} else {
				failures++;
			}
		}
	}
	vmi_perf_print_summary("gcm_decrypt", vmi_perf_samples, k,
			       failures);
}

static void perf_test_va_to_pa(struct rec *rec)
{
    struct sysreg_state *sysregs = &rec->sysregs;
    unsigned long ttbr1 = (unsigned long)sysregs->ttbr1_el1;
    unsigned long current = (unsigned long)rec->sp_el0;
    unsigned long pa = 0;
    unsigned long t1, t2, ret;
    unsigned int failures = 0U;
    unsigned int i;
    unsigned int k = 0U;

    spinlock_acquire(&vmi_perf_lock);

    vmi_log_guest_ctx(rec, "va_to_pa");

    /* Sanity check: target VA must be a kernel address */
    if (current < 0xffff000000000000UL) {
        spinlock_release(&vmi_perf_lock);
        ERROR(">>> PERF va_to_pa: invalid current VA 0x%lx <<<\n", current);
        return;
    }

    /* Run 1010 iterations: first 10 warmup (discarded), then 1000 measured */
    for (i = 0U; i < VMI_PERF_WARMUP + VMI_PERF_SAMPLES; i++) {
        t1 = perf_cycles();
        ret = vmi_va_to_pa(rec, current, ttbr1, &pa);
        t2 = perf_cycles();
        if (i >= VMI_PERF_WARMUP) {
            if (ret == 0UL)
                vmi_perf_samples[k++] = t2 - t1;
            else
                failures++;
        }
    }

    vmi_perf_print_summary("va_to_pa", vmi_perf_samples, k, failures);
}

static void perf_test_read_pa(struct rec *rec)
{
    struct sysreg_state *sysregs = &rec->sysregs;
    unsigned long ttbr1 = (unsigned long)sysregs->ttbr1_el1;
    unsigned long current = (unsigned long)rec->sp_el0;
    unsigned long pa = 0, val = 0;
    unsigned long t1, t2, ret;
    unsigned int failures = 0U;
    unsigned int i;
    unsigned int k = 0U;

    spinlock_acquire(&vmi_perf_lock);

    vmi_log_guest_ctx(rec, "read_pa");

    if (current < 0xffff000000000000UL) {
        spinlock_release(&vmi_perf_lock);
        ERROR(">>> PERF read_pa: invalid current VA 0x%lx <<<\n", current);
        return;
    }

    /* First translate current VA to PA (one-shot, not measured) */
    ret = vmi_va_to_pa(rec, current, ttbr1, &pa);
    if (ret != 0UL) {
        spinlock_release(&vmi_perf_lock);
        ERROR(">>> PERF read_pa: va_to_pa failed ret=%lu <<<\n", ret);
        return;
    }

    /* Run 1010 iterations: first 10 warmup, then 1000 measured */
    for (i = 0U; i < VMI_PERF_WARMUP + VMI_PERF_SAMPLES; i++) {
        t1 = perf_cycles();
        ret = vmi_read_pa(rec, pa, &val);
        t2 = perf_cycles();
        if (i >= VMI_PERF_WARMUP) {
            if (ret == 0UL)
                vmi_perf_samples[k++] = t2 - t1;
            else
                failures++;
        }
    }

    vmi_perf_print_summary("read_pa", vmi_perf_samples, k, failures);
}

static void perf_test_p1(struct rec *rec, unsigned long max_procs)
{
    struct sysreg_state *sysregs = &rec->sysregs;
    unsigned long ttbr1 = (unsigned long)sysregs->ttbr1_el1;
    unsigned long start_task = 0xffff800082b45080UL;
    unsigned long tasks_off = 0x3F0UL;
    unsigned long pid_off = 0x4C0UL;
    unsigned long comm_off = 0x6A8UL;
    unsigned long pa = 0, val = 0, ret;
    unsigned long last_va_to_pa = 0UL;
    unsigned long last_read_pa = 0UL;
    unsigned int last_procs = 0U;
    unsigned int failures = 0U;
    unsigned int limit;
    unsigned int samples = 0U;
    int iter, count;
    unsigned long t1, t2;

    vmi_log_guest_ctx(rec, "p1");

    if (start_task < 0xffff000000000000UL) {
        ERROR(">>> PERF p1: invalid start_task 0x%lx <<<\n", start_task);
        return;
    }

    if ((max_procs == 0UL) || (max_procs > 50UL)) {
        limit = 50U;
    } else {
        limit = (unsigned int)max_procs;
    }

    spinlock_acquire(&vmi_perf_lock);

    /* 55 iterations: first 5 warmup (discarded), then 50 measured */
    for (iter = 0; iter < 55; iter++) {
        unsigned long va_to_pa_calls = 0UL;
        unsigned long read_pa_calls = 0UL;
        unsigned int procs = 0U;
        bool scan_failed = false;

        t1 = perf_cycles();

        unsigned long task = start_task;
        va_to_pa_calls++;
        ret = vmi_va_to_pa(rec, task, ttbr1, &pa);
        if (ret != 0UL) {
            t2 = perf_cycles();
            if (iter >= 5) {
                failures++;
                last_procs = procs;
                last_va_to_pa = va_to_pa_calls;
                last_read_pa = read_pa_calls;
            }
            continue;
        }

        for (count = 0; count < (int)limit; count++) {
            unsigned long c1 = 0, c2 = 0;
            unsigned long next_t;
            unsigned long next_task;
            int pid_v = 0;

            procs++;

            /* Read comm (16 bytes) */
            va_to_pa_calls++;
            ret = vmi_va_to_pa(rec, task + comm_off, ttbr1, &pa);
            if (ret != 0UL) {
                scan_failed = true;
                break;
            }
            read_pa_calls++;
            (void)vmi_read_pa(rec, pa, &c1);

            va_to_pa_calls++;
            ret = vmi_va_to_pa(rec, task + comm_off + 8, ttbr1, &pa);
            if (ret != 0UL) {
                scan_failed = true;
                break;
            }
            read_pa_calls++;
            (void)vmi_read_pa(rec, pa, &c2);

            /* Read pid */
            va_to_pa_calls++;
            ret = vmi_va_to_pa(rec, task + pid_off, ttbr1, &pa);
            if (ret != 0UL) {
                scan_failed = true;
                break;
            }
            read_pa_calls++;
            (void)vmi_read_pa(rec, pa, &val);
            pid_v = (int)(val & 0xFFFFFFFF);

            /* Suppress unused-but-set warning */
            (void)c1; (void)c2; (void)pid_v;

            if (procs >= limit) {
                break;
            }

            /* Walk to next task via tasks list */
            va_to_pa_calls++;
            ret = vmi_va_to_pa(rec, task + tasks_off, ttbr1, &pa);
            if (ret != 0UL) {
                scan_failed = true;
                break;
            }
            read_pa_calls++;
            (void)vmi_read_pa(rec, pa, &next_t);
            next_task = next_t - tasks_off;
            if (next_task == start_task) {
                break;
            }
            task = next_task;
        }

        t2 = perf_cycles();
        if (iter >= 5) {
            if (!scan_failed) {
                vmi_perf_samples[samples++] = t2 - t1;
            } else {
                failures++;
            }
            last_procs = procs;
            last_va_to_pa = va_to_pa_calls;
            last_read_pa = read_pa_calls;
        }
    }

    vmi_perf_print_summary("p1_scan", vmi_perf_samples, samples,
                           failures);
    ERROR("PERF_P1_CALLS,procs=%u,va_to_pa=%lu,read_pa=%lu\n",
          last_procs, last_va_to_pa, last_read_pa);
}

static void perf_test_p5(struct rec *rec)
{
    struct sysreg_state *sysregs = &rec->sysregs;
    unsigned long ttbr1 = (unsigned long)sysregs->ttbr1_el1;
    unsigned long vbar = sysregs->vbar_el1;
    unsigned long stext, scan_start, scan_end, code_lo, code_hi;
    unsigned long sct_va = 0;
    unsigned long pa = 0, val = 0, ret;
    unsigned long addr;
    unsigned long t1, t2;
    unsigned long candidates = 0UL;
    unsigned long va_to_pa_calls = 0UL;
    unsigned long read_pa_calls = 0UL;
    unsigned long read_pa_successes = 0UL;
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

        candidates++;
        for (k = 0; k < 8; k++) {
            va_to_pa_calls++;
            ret = vmi_va_to_pa(rec, addr + (unsigned long)k * 8UL, ttbr1, &pa);
            if (ret != 0UL) break;
            read_pa_calls++;
            ret = vmi_read_pa(rec, pa, &val);
            if (ret != 0UL) break;
            read_pa_successes++;
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
    ERROR("PERF_P5_CALLS,candidates=%lu,va_to_pa=%lu,read_pa=%lu,"
          "read_ok=%lu\n",
          candidates, va_to_pa_calls, read_pa_calls, read_pa_successes);
}

#endif /* CONFIG_VMI_PERF_EVAL */

/* Read task->cred->uid: cred pointer at task+0x698, uid low 32 bits at cred+0x8. */
static unsigned long vmi_read_cred_uid(struct rec *rec,
				      unsigned long task_va,
				      unsigned long ttbr1,
				      unsigned int *uid_out)
{
	unsigned long pa = 0UL, cred_va = 0UL, val = 0UL, ret;

	ret = vmi_va_to_pa(rec, task_va + 0x698UL, ttbr1, &pa);
	if (ret != 0UL) {
		return ret;
	}
	if (vmi_read_pa(rec, pa, &cred_va) != 0UL) {
		return 1UL;
	}
	if (cred_va < 0xffff000000000000UL) {
		return 1UL;
	}
	ret = vmi_va_to_pa(rec, cred_va + 0x8UL, ttbr1, &pa);
	if (ret != 0UL) {
		return ret;
	}
	if (vmi_read_pa(rec, pa, &val) != 0UL) {
		return 1UL;
	}
	*uid_out = (unsigned int)(val & 0xFFFFFFFFUL);
	return 0UL;
}

/* Monitored process comm first 8 bytes, packed little-endian. */
#ifndef VMI_VICTIM_COMM8
#define VMI_VICTIM_COMM8 0x0000000000636976UL
#endif

#ifndef VMI_SCAN_VERBOSE
#define VMI_SCAN_VERBOSE 0 /* 1=每进程打一行 trace（调试），0=只打 DETECTED */
#endif

static void vmi_cred_scan(struct rec *rec)
{
	unsigned long ttbr1 = (unsigned long)rec->sysregs.ttbr1_el1;
	unsigned long start_task = 0xffff800082b45080UL; /* &init_task */
	unsigned long task = start_task, pa = 0UL, c1 = 0UL, next_t = 0UL, ret;
	unsigned int uid = 0U;
	unsigned long t_begin, t_end;
	int count;

	if (start_task < 0xffff000000000000UL) {
		return;
	}
	t_begin = perf_cycles();
	for (count = 0; count < 200; count++) {
		c1 = 0UL;
		ret = vmi_va_to_pa(rec, task + 0x6A8UL, ttbr1, &pa);
		if (ret == 0UL) {
			(void)vmi_read_pa(rec, pa, &c1);
		}
		if (vmi_read_cred_uid(rec, task, ttbr1, &uid) == 0UL) {
#if VMI_SCAN_VERBOSE
			ERROR("VMI_SCAN task=0x%lx comm8=0x%lx uid=%u\n",
			      task, c1, uid);
#endif
			if ((c1 == VMI_VICTIM_COMM8) && (uid == 0U)) {
				ERROR("VMI_SCAN DETECTED victim uid=0 task=0x%lx\n",
				      task);
			}
		}
		ret = vmi_va_to_pa(rec, task + 0x3F0UL, ttbr1, &pa);
		if (ret != 0UL) {
			break;
		}
		if (vmi_read_pa(rec, pa, &next_t) != 0UL) {
			break;
		}
		{
			unsigned long next_task = next_t - 0x3F0UL;

			if ((next_task == start_task) || (count >= 49)) {
				break;
			}
			task = next_task;
		}
	}
	t_end = perf_cycles();
	ERROR("VMI_SCAN window begin=%lu end=%lu dur=%lu cyc "
	      "(single REC_ENTER, realm frozen)\n",
	      t_begin, t_end, t_end - t_begin);
}

static inline unsigned long vmi_periodic_next_interval(struct rec *rec)
{
	unsigned long cntpct;

	isb();
	cntpct = read_cntpct_el0();
	return VMI_PERIODIC_MIN +
	       ((cntpct ^ (unsigned long)rec->pc) & VMI_PERIODIC_MASK);
}

bool vmi_handle(struct rec *rec, struct rmi_rec_run *rec_run)
{
	if (vmi_periodic_enabled) {
		if (vmi_periodic_remaining == 0UL) {
			vmi_periodic_remaining = vmi_periodic_next_interval(rec);
		}

		vmi_periodic_remaining--;
		if (vmi_periodic_remaining == 0UL) {
			vmi_cred_scan(rec);
			vmi_periodic_remaining = vmi_periodic_next_interval(rec);
		}
	}

	if ((rec_run->enter.flags & (1UL << 63)) == 0UL) {
		return false;
	}

	if (rec_run->enter.gprs[0] == 0UL) {
		rec_run->enter.flags &= ~(1UL << 63);
		return false;
	}

	unsigned long vmi_cmd = rec_run->enter.gprs[0];
	unsigned long vmi_arg0 = rec_run->enter.gprs[1];
	struct sysreg_state *sysregs = &rec->sysregs;
	unsigned long vmi_result = 0;

	vmi_cnt_freq = read_cntfrq_el0();

	switch (vmi_cmd) {
	case 1: {
		unsigned long val;
		if (vmi_read_pa(rec, vmi_arg0, &val) == 0UL) {
			vmi_result = val;
			ERROR(">>> VMI_CMD[READ_PA] addr=0x%lx val=0x%lx <<<\n", vmi_arg0, val);
		} else {
			ERROR(">>> VMI_CMD[READ_PA] addr=0x%lx FAILED <<<\n", vmi_arg0);
		}
		break;
	}
	case 2: {
		unsigned long ttbr1 = sysregs->ttbr1_el1;
		unsigned long pa, val;
		unsigned long va2pa_ret;

		va2pa_ret = vmi_va_to_pa(rec, vmi_arg0, ttbr1, &pa);
		if (va2pa_ret == 0UL) {
			struct s2_walk_result _wr;
			enum s2_walk_status _ws;

			_ws = realm_ipa_to_pa(rec, pa & GRANULE_MASK, &_wr);
			if (_ws == WALK_SUCCESS) {
#if !VMI_PERF_MEASURE
				ERROR(">>> VMI DBG: stage2(ipa=0x%lx) -> machine_pa=0x%lx <<<\n",
				      pa, _wr.pa);
#endif
				granule_unlock(_wr.llt);
			} else {
#if !VMI_PERF_MEASURE
				ERROR(">>> VMI DBG: stage2(ipa=0x%lx) FAILED ws=%d <<<\n",
				      pa, (int)_ws);
#endif
			}
		}

		if (va2pa_ret == 0UL &&
		    vmi_read_pa(rec, pa, &val) == 0UL) {
			vmi_result = val;
			ERROR(">>> VMI_CMD[READ_VA] va=0x%lx pa=0x%lx val=0x%lx <<<\n", vmi_arg0, pa, val);
		} else {
			ERROR(">>> VMI_CMD[READ_VA] va=0x%lx FAILED <<<\n", vmi_arg0);
		}
		break;
	}
	case 3: {
		unsigned long reg_val = 0;
		switch (vmi_arg0) {
		case 0: reg_val = sysregs->ttbr0_el1; break;
		case 1: reg_val = sysregs->ttbr1_el1; break;
		case 2: reg_val = sysregs->sp_el0; break;
		case 3: reg_val = sysregs->tcr_el1; break;
		case 4: reg_val = sysregs->sctlr_el1; break;
		case 5: reg_val = sysregs->vbar_el1; break;
		default: break;
		}
		vmi_result = reg_val;
		ERROR(">>> VMI_CMD[GET_REG] reg=%lu val=0x%lx <<<\n", vmi_arg0, reg_val);
		break;
	}
	case 4:
		vmi_result = vmi_setup_trap(rec, vmi_arg0);
		ERROR(">>> VMI_CMD[SETUP_TRAP] ipa=0x%lx result=%lu <<<\n",
		      vmi_arg0, vmi_result);
		break;
	case 5:
		vmi_result = vmi_handle_trap(rec, rec_run->exit.esr,
					     rec_run->exit.hpfar);
		if (vmi_result == 0UL) {
			vmi_result = vmi_restore_trap(rec);
		}
		ERROR(">>> VMI_CMD[HANDLE_TRAP] result=%lu <<<\n", vmi_result);
		break;
	case 6:
		vmi_result = vmi_last_fipa;
		ERROR(">>> VMI_CMD[GET_FIPA]=0x%lx <<<\n", vmi_last_fipa);
		break;
		case 7:
			vmi_result = vmi_hit_count;
			ERROR(">>> VMI_CMD[GET_COUNT]=%lu <<<\n", vmi_hit_count);
			break;
		case 8:
			vmi_result = vmi_last_cycles;
			break;
		case 9:
			vmi_result = vmi_total_cycles;
			break;
		case 10:
			vmi_result = vmi_cnt_freq;
			break;
		case 11:
			vmi_result = vmi_setup_cycles;
			break;
		case 20:
			vmi_periodic_enabled = (vmi_arg0 != 0UL);
			if (vmi_periodic_enabled) {
				vmi_periodic_remaining = vmi_periodic_next_interval(rec);
			}
			vmi_result = vmi_periodic_enabled ? 1UL : 0UL;
			ERROR(">>> VMI_CMD[PERIODIC_EN]=%lu <<<\n",
			      vmi_result);
			break;
		case 22:
			vmi_cred_scan(rec);
			vmi_result = 0UL;
			ERROR(">>> VMI_CMD[CRED_SCAN] done <<<\n");
			break;
	#ifdef CONFIG_VMI_PERF_EVAL
		case 100: perf_test_aes();         vmi_result = 0; ERROR(">>> VMI_CMD[PERF_AES] done <<<\n"); break;
	case 101: perf_test_va_to_pa(rec); vmi_result = 0; ERROR(">>> VMI_CMD[PERF_VA_TO_PA] done <<<\n"); break;
	case 102: perf_test_read_pa(rec);  vmi_result = 0; ERROR(">>> VMI_CMD[PERF_READ_PA] done <<<\n"); break;
	case 103: perf_test_p1(rec, vmi_arg0); vmi_result = 0; ERROR(">>> VMI_CMD[PERF_P1] done <<<\n"); break;
	case 104: perf_test_p5(rec);       vmi_result = 0; ERROR(">>> VMI_CMD[PERF_P5] done <<<\n"); break;
	case 105: perf_test_gcm();         vmi_result = 0;
		  ERROR(">>> VMI_CMD[PERF_GCM] done <<<\n");
		  break;
	case 106: {
		unsigned char plaintext[VMI_AEAD_PLAINTEXT_SIZE];
		struct vmi_aead_record record;
		unsigned long seq;
		unsigned long fixed_result = 0x1122334455667788UL;
		unsigned long fixed_cmd = 0x00000000000000AAUL;
		int ret106;
		int i;

		(void)memcpy(&plaintext[0], &fixed_result,
			     sizeof(fixed_result));
		(void)memcpy(&plaintext[8], &fixed_cmd,
			     sizeof(fixed_cmd));

		seq = __atomic_fetch_add(&vmi_tx_sequence, 1UL,
					 __ATOMIC_RELAXED);
		ret106 = vmi_channel_encrypt(seq, plaintext,
					     sizeof(plaintext), &record);
		if (ret106 == 0) {
			ERROR("CMD106 seq=%016lx\n", record.sequence);
			ERROR("CMD106 ct=");
			for (i = 0;
			     i < (int)sizeof(record.ciphertext); i++) {
				ERROR("%02x", record.ciphertext[i]);
			}
			ERROR("\n");
			ERROR("CMD106 tag=");
			for (i = 0; i < (int)sizeof(record.tag); i++) {
				ERROR("%02x", record.tag[i]);
			}
			ERROR("\n");
		} else {
			ERROR("CMD106 FAIL,%d\n", ret106);
		}
		vmi_result = 0;
		break;
	}
	case 107: {
		unsigned char plaintext[VMI_AEAD_PLAINTEXT_SIZE];
		unsigned char decrypted[VMI_AEAD_PLAINTEXT_SIZE];
		struct vmi_aead_record record;
		struct vmi_aead_record tampered;
		unsigned long fixed_result = 0x1122334455667788UL;
		unsigned long fixed_cmd = 0x00000000000000AAUL;
		unsigned long seq;
		unsigned long r;
		unsigned long c;
		int ret;
		int i;

		/*
		 * Fixed little-endian plaintext, matching cmd 106:
		 * 88 77 66 55 44 33 22 11 aa 00 00 00 00 00 00 00
		 */
		(void)memcpy(&plaintext[0], &fixed_result, 8U);
		(void)memcpy(&plaintext[8], &fixed_cmd, 8U);

		seq = __atomic_fetch_add(&vmi_tx_sequence, 1UL,
					 __ATOMIC_RELAXED);

		ret = vmi_diag_encrypt_dir(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM, seq,
			plaintext, sizeof(plaintext), &record);
		if (ret != 0) {
			ERROR("CMD107 ENC_FAIL,%d\n", ret);
			vmi_result = 0;
			break;
		}

		ERROR("CMD107 dir=%02x seq=%016lx\n",
		      (unsigned int)VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
		      record.sequence);
		ERROR("CMD107 ct=");
		for (i = 0; i < (int)sizeof(record.ciphertext); i++) {
			ERROR("%02x", record.ciphertext[i]);
		}
		ERROR("\n");
		ERROR("CMD107 tag=");
		for (i = 0; i < (int)sizeof(record.tag); i++) {
			ERROR("%02x", record.tag[i]);
		}
		ERROR("\n");

		ret = vmi_channel_decrypt(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
			record.sequence, &record, decrypted,
			sizeof(decrypted));
		if ((ret == 0) &&
		    (memcmp(decrypted, plaintext, sizeof(plaintext)) == 0)) {
			(void)memcpy(&r, &decrypted[0], 8U);
			(void)memcpy(&c, &decrypted[8], 8U);
			ERROR("CMD107 decrypt=OK result=%016lx cmd=%016lx\n",
			      r, c);
		} else {
			ERROR("CMD107 decrypt=FAIL ret=%d\n", ret);
		}

		tampered = record;
		tampered.tag[0] ^= 0xFFU;
		ret = vmi_channel_decrypt(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
			tampered.sequence, &tampered, decrypted,
			sizeof(decrypted));
		if (ret != 0) {
			ERROR("CMD107 tamper=REJECTED ret=%d\n", ret);
		} else {
			ERROR("CMD107 tamper=ACCEPTED_BUG\n");
		}

		vmi_result = 0;
		break;
	}
	case 108: {
		struct vmi_rx_replay test_rx = { 0UL, false };
		unsigned char plaintext[VMI_AEAD_PLAINTEXT_SIZE];
		unsigned char out[VMI_AEAD_PLAINTEXT_SIZE];
		struct vmi_aead_record rec;
		unsigned long fixed_result = 0x1122334455667788UL;
		unsigned long fixed_cmd = 0x00000000000000AAUL;
		unsigned long seq;
		const char *label;
		int enc_ret;
		int ret;
		int all_ok = 1;
		bool pass;

		(void)memcpy(&plaintext[0], &fixed_result, 8U);
		(void)memcpy(&plaintext[8], &fixed_cmd, 8U);

		/* a) First authenticated record is accepted. */
		label = "first";
		seq = 100UL;
		enc_ret = vmi_diag_encrypt_dir(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM, seq,
			plaintext, sizeof(plaintext), &rec);
		if (enc_ret == 0) {
			ret = vmi_channel_receive(
				&test_rx, VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
				&rec, out, sizeof(out));
		} else {
			ret = enc_ret;
		}
		pass = ((enc_ret == 0) && (ret == VMI_RX_OK));
		ERROR("CMD108 %s seq=%lu ret=%d %s\n",
		      label, seq, ret, pass ? "PASS" : "FAIL");
		if (!pass) {
			all_ok = 0;
		}

		/* b) A strictly newer authenticated record is accepted. */
		label = "newer";
		seq = 101UL;
		enc_ret = vmi_diag_encrypt_dir(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM, seq,
			plaintext, sizeof(plaintext), &rec);
		if (enc_ret == 0) {
			ret = vmi_channel_receive(
				&test_rx, VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
				&rec, out, sizeof(out));
		} else {
			ret = enc_ret;
		}
		pass = ((enc_ret == 0) && (ret == VMI_RX_OK));
		ERROR("CMD108 %s seq=%lu ret=%d %s\n",
		      label, seq, ret, pass ? "PASS" : "FAIL");
		if (!pass) {
			all_ok = 0;
		}

		/* c) A previously accepted sequence is rejected as replay. */
		label = "replay";
		seq = 100UL;
		enc_ret = vmi_diag_encrypt_dir(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM, seq,
			plaintext, sizeof(plaintext), &rec);
		if (enc_ret == 0) {
			ret = vmi_channel_receive(
				&test_rx, VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
				&rec, out, sizeof(out));
		} else {
			ret = enc_ret;
		}
		pass = ((enc_ret == 0) && (ret == VMI_RX_REPLAY));
		ERROR("CMD108 %s seq=%lu ret=%d %s\n",
		      label, seq, ret, pass ? "PASS" : "FAIL");
		if (!pass) {
			all_ok = 0;
		}

		/* d) An older authenticated sequence is also rejected. */
		label = "older";
		seq = 50UL;
		enc_ret = vmi_diag_encrypt_dir(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM, seq,
			plaintext, sizeof(plaintext), &rec);
		if (enc_ret == 0) {
			ret = vmi_channel_receive(
				&test_rx, VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
				&rec, out, sizeof(out));
		} else {
			ret = enc_ret;
		}
		pass = ((enc_ret == 0) && (ret == VMI_RX_REPLAY));
		ERROR("CMD108 %s seq=%lu ret=%d %s\n",
		      label, seq, ret, pass ? "PASS" : "FAIL");
		if (!pass) {
			all_ok = 0;
		}

		/*
		 * e) Authentication failure must be rejected without advancing
		 * replay state.
		 */
		label = "tampered";
		seq = 102UL;
		enc_ret = vmi_diag_encrypt_dir(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM, seq,
			plaintext, sizeof(plaintext), &rec);
		if (enc_ret == 0) {
			rec.tag[0] ^= 0xFFU;
			ret = vmi_channel_receive(
				&test_rx, VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
				&rec, out, sizeof(out));
		} else {
			ret = enc_ret;
		}
		pass = ((enc_ret == 0) && (ret < 0));
		ERROR("CMD108 %s seq=%lu ret=%d %s\n",
		      label, seq, ret, pass ? "PASS" : "FAIL");
		if (!pass) {
			all_ok = 0;
		}

		/*
		 * f) The untampered record with the same sequence must still be
		 * accepted, proving the failed authentication did not advance
		 * replay state.
		 */
		label = "post-tamper";
		seq = 102UL;
		enc_ret = vmi_diag_encrypt_dir(
			VMI_CHANNEL_DIRECTION_HOST_TO_RMM, seq,
			plaintext, sizeof(plaintext), &rec);
		if (enc_ret == 0) {
			ret = vmi_channel_receive(
				&test_rx, VMI_CHANNEL_DIRECTION_HOST_TO_RMM,
				&rec, out, sizeof(out));
		} else {
			ret = enc_ret;
		}
		pass = ((enc_ret == 0) && (ret == VMI_RX_OK));
		ERROR("CMD108 %s seq=%lu ret=%d %s\n",
		      label, seq, ret, pass ? "PASS" : "FAIL");
		if (!pass) {
			all_ok = 0;
		}

		if (all_ok != 0) {
			ERROR("CMD108 replay-test=ALLPASS\n");
		} else {
			ERROR("CMD108 replay-test=FAIL\n");
		}

		vmi_result = 0;
		break;
	}
#endif
	default:
		ERROR(">>> VMI_CMD[%lu] unknown command <<<\n", vmi_cmd);
		break;
	}

	rec_run->exit.vmi_record_version = 0U;

	if ((vmi_cmd >= 1UL) && (vmi_cmd <= 11UL)) {
		unsigned char vmi_enc_plaintext[VMI_AEAD_PLAINTEXT_SIZE];
		unsigned long vmi_enc_seq;
		int vmi_enc_ret;
		int vmi_enc_i;

		(void)memcpy(&vmi_enc_plaintext[0], &vmi_result, 8U);
		(void)memcpy(&vmi_enc_plaintext[8], &vmi_cmd, 8U);

		vmi_enc_seq = __atomic_fetch_add(&vmi_tx_sequence, 1UL,
						 __ATOMIC_RELAXED);
		vmi_enc_ret = vmi_channel_encrypt(
			vmi_enc_seq, vmi_enc_plaintext,
			sizeof(vmi_enc_plaintext),
			&rec_run->exit.vmi_encrypted);
		if (vmi_enc_ret == 0) {
			rec_run->exit.vmi_record_version =
				VMI_AEAD_RECORD_VERSION;

			ERROR("VMIENC seq=%016lx\n",
			      rec_run->exit.vmi_encrypted.sequence);
			ERROR("VMIENC ct=");
			for (vmi_enc_i = 0;
			     vmi_enc_i <
			     (int)sizeof(rec_run->exit.vmi_encrypted.ciphertext);
			     vmi_enc_i++) {
				ERROR("%02x",
				      rec_run->exit.vmi_encrypted
					      .ciphertext[vmi_enc_i]);
			}
			ERROR("\n");
			ERROR("VMIENC tag=");
			for (vmi_enc_i = 0;
			     vmi_enc_i <
			     (int)sizeof(rec_run->exit.vmi_encrypted.tag);
			     vmi_enc_i++) {
				ERROR("%02x",
				      rec_run->exit.vmi_encrypted.tag[vmi_enc_i]);
			}
			ERROR("\n");
		} else {
			ERROR("VMIENC FAIL,%d\n", vmi_enc_ret);
		}
	}

	rec_run->exit.gprs[0] = vmi_result;
	rec_run->exit.exit_reason = RMI_EXIT_HOST_CALL;
	rec_run->enter.flags &= ~(1UL << 63);
	rec_run->enter.gprs[0] = 0;
	rec_run->enter.gprs[1] = 0;
	ERROR(">>> VMI_CMD handled <<<\n");
	return true;
}

#endif /* CONFIG_RMM_VMI */
