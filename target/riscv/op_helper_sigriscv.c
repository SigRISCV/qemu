#include "qemu/osdep.h"

#ifdef TARGET_SIGRISCV

#include "cpu.h"
#include "exec/helper-proto.h"
#include "target/riscv/cpu_bits.h"
#include "qarma.h"

static inline void sigriscv_setgprid_checkpriv(CPUArchState *env, uint32_t gpr_idx, target_ulong id)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    if (env->priv == PRV_U && gpr_idx != 0) {
        riscv_env->gpr_id[gpr_idx] = id;
    }
}

static inline target_ulong sigriscv_getgprid_checkpriv(CPUArchState *env, uint32_t gpr_idx)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    if (env->priv == PRV_U) {
        return riscv_env->gpr_id[gpr_idx] & SIGCSR_ID_MASK;
    }
    return 0;
}

static void get_sigriscv_key(CPURISCVState *env, target_ulong *kl, target_ulong *kh)
{
    if (env->priv == PRV_U) {
        *kl = env->skey[0];
        *kh = env->skey[1];
    } else {
        *kl = env->mkey[0];
        *kh = env->mkey[1];
    }
}

static inline bool is_sigriscv_use_enabled(CPUArchState *env)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    return env->priv != PRV_U || (riscv_env->idcsr & IDCSR_USE) != 0;
}

static target_ulong sigriscv_decrypt(CPUArchState *env,
                                         target_ulong secret,
                                         target_ulong addr,
                                         uint32_t rs1_idx)
{
    // printf("decrypt: secret = %lx, addr = %lx, rs1_idx = %u, rd_idx = %u\n", secret, addr, rs1_idx, rd_idx);
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    target_ulong keyl, keyh;
    get_sigriscv_key(riscv_env, &keyl, &keyh);

    target_ulong base_id = sigriscv_getgprid_checkpriv(env, rs1_idx);
    target_ulong addr_lower = addr & SIGCSR_PTR_MASK;
    target_ulong base_id_shifted = base_id << SIGCSR_ID_SHIFT;
    target_ulong new_tweak = base_id_shifted | addr_lower;
    // printf("decrypt: base_id = %lx, addr_lower = %lx, new_tweak = %lx\n", base_id, addr_lower, new_tweak);
    
    target_ulong plaintext = qarma64_dec(secret, new_tweak, keyl, keyh, 7);
    return plaintext;
}

static target_ulong sigriscv_decrypt_setid_addr(CPUArchState *env,
                                         target_ulong secret,
                                         target_ulong addr,
                                         uint32_t rs1_idx,
                                         uint32_t rd_idx)
{
    // printf("decrypt: secret = %lx, addr = %lx, rs1_idx = %u, rd_idx = %u\n", secret, addr, rs1_idx, rd_idx);
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    target_ulong pointer_with_id = sigriscv_decrypt(env, secret, addr, rs1_idx);
    target_ulong new_id = (pointer_with_id >> SIGCSR_ID_SHIFT) & SIGCSR_ID_MASK;
    sigriscv_setgprid_checkpriv(env, rd_idx, new_id);
    target_ulong pointer = (target_ulong)(((target_long)(pointer_with_id << SIGCSR_ID_BITS)) >> SIGCSR_ID_BITS);
    // printf("decrypt: pointer_with_id = %lx, new_id = %lx, pointer = %lx\n", pointer_with_id, new_id, pointer);
    return pointer;
}

target_ulong HELPER(sigriscv_decrypt_setid)(CPUArchState *env,
                                         target_ulong secret,
                                         target_ulong addr,
                                         uint32_t rs1_idx,
                                         uint32_t rd_idx)
{
    if (!is_sigriscv_use_enabled(env)) {
        return secret;
    }
    return sigriscv_decrypt_setid_addr(env, secret, addr, rs1_idx, rd_idx);
}

target_ulong HELPER(sigriscv_decrypt_setid_encmap)(CPUArchState *env,
                                         target_ulong secret,
                                         target_ulong addr,
                                         uint32_t rs1_idx,
                                         uint32_t rd_idx)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    if (!is_sigriscv_use_enabled(env)) {
        return secret;
    }
    if (rd_idx == 0) {
        // target_ulong plain = sigriscv_decrypt(env, secret, addr, rs1_idx);
        // riscv_env->encmap = plain;
        riscv_env->encmap = secret;
        return 0;
    }
    if (!(riscv_env->encmap & (1ULL << rd_idx))) {
        sigriscv_setgprid_checkpriv(env, rd_idx, 0);
        return secret;
    }
    return sigriscv_decrypt_setid_addr(env, secret, addr, rs1_idx, rd_idx);
}

static target_ulong sigriscv_encrypt(CPUArchState *env,
                                         target_ulong plain,
                                         target_ulong addr,
                                         uint32_t rs1_idx)
{
    // printf("encrypt: secret = %lx, addr = %lx, rs1_idx = %u\n", secret, addr, rs1_idx);
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    target_ulong keyl, keyh;
    get_sigriscv_key(riscv_env, &keyl, &keyh);

    target_ulong base_id = sigriscv_getgprid_checkpriv(env, rs1_idx);
    target_ulong addr_lower = addr & SIGCSR_PTR_MASK;
    target_ulong base_id_shifted = base_id << SIGCSR_ID_SHIFT;
    target_ulong new_tweak = base_id_shifted | addr_lower;
    // printf("encrypt: base_id = %lx, addr_lower = %lx, new_tweak = %lx\n", base_id, addr_lower, new_tweak);

    target_ulong secret = qarma64_enc(plain, new_tweak, keyl, keyh, 7);
    return secret;
}

static target_ulong sigriscv_encrypt_addr(CPUArchState *env,
                                         target_ulong plain,
                                         target_ulong addr,
                                         uint32_t rs1_idx,
                                         uint32_t rs2_idx)
{
    // printf("encrypt: secret = %lx, addr = %lx, rs1_idx = %u, rs2_idx = %u\n", secret, addr, rs1_idx, rs2_idx);
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    target_ulong base_id = sigriscv_getgprid_checkpriv(env, rs2_idx);
    target_ulong plain_lower = plain & SIGCSR_PTR_MASK;
    target_ulong base_id_shifted = base_id << SIGCSR_ID_SHIFT;
    target_ulong new_plain = base_id_shifted | plain_lower;
    target_ulong secret = sigriscv_encrypt(env, new_plain, addr, rs1_idx);
    // printf("encrypt: new_plain = %lx, secret = %lx\n", new_plain, secret);
    return secret;
}

target_ulong HELPER(sigriscv_encrypt_withid)(CPUArchState *env,
                                         target_ulong plain,
                                         target_ulong addr,
                                         uint32_t rs1_idx,
                                         uint32_t rs2_idx)
{
    if (!is_sigriscv_use_enabled(env)) {
        return plain;
    }
    return sigriscv_encrypt_addr(env, plain, addr, rs1_idx, rs2_idx);
}

target_ulong HELPER(sigriscv_encrypt_withid_encmap)(CPUArchState *env,
                                         target_ulong plain,
                                         target_ulong addr,
                                         uint32_t rs1_idx,
                                         uint32_t rs2_idx)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    if (!is_sigriscv_use_enabled(env)) {
        return plain;
    }
    if (rs2_idx == 0) {
        // target_ulong plain = riscv_env->encmap;
        // plain = sigriscv_encrypt(env, plain, addr, rs1_idx);
        return riscv_env->encmap;
    }
    if (riscv_env->gpr_id[rs2_idx] == 0) {
        riscv_env->encmap &= ~(1ULL << rs2_idx);
        return plain;
    }
    riscv_env->encmap |= (1ULL << rs2_idx);
    return sigriscv_encrypt_addr(env, plain, addr, rs1_idx, rs2_idx);
}

target_ulong helper_sigriscv_get_gpr_id(CPUArchState *env, uint32_t reg)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    
    assert(reg < SIGCSR_GPRID_NUM);

    return riscv_env->gpr_id[reg] & SIGCSR_ID_MASK;
}

void helper_sigriscv_set_gpr_id(CPUArchState *env, uint32_t reg, target_ulong id)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;

    // Check USE bit in U-mode (bit 30 of idcsr)
    if (!is_sigriscv_use_enabled(env)) {
        return;
    }

    sigriscv_setgprid_checkpriv(env, reg, id);
}

void helper_sigriscv_set_gpr_newid(CPUArchState *env, uint32_t reg)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;

    // Check USE bit in U-mode (bit 30 of idcsr)
    if (!is_sigriscv_use_enabled(env)) {
        return;
    }

    target_ulong id = riscv_env->idcsr & IDCSR_COUNTER_MASK;
    sigriscv_setgprid_checkpriv(env, reg, id);
    id = (id + 1) & IDCSR_COUNTER_MASK;
    if (id == 0 || id == 1) id = 2; // Skip reserved values 0 and 1
    riscv_env->idcsr = (riscv_env->idcsr & (~IDCSR_COUNTER_MASK)) | id;
}

static target_ulong sigriscv_hash_callee_regs(CPUArchState *env)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    target_ulong hash = 0;
    
    // Hash callee-saved registers: s0-s11 (x8-x9, x18-x27) and sp (x2)
    static const int callee_saved_regs[] = {
        2,   /* sp */
        8, 9,   /* s0, s1 */
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27  /* s2-s11 */
    };
    
    for (int i = 0; i < sizeof(callee_saved_regs) / sizeof(callee_saved_regs[0]); i++) {
        int reg = callee_saved_regs[i];
        target_ulong val = riscv_env->gpr[reg];
        // printf("Hashing reg x%d: val=0x%lx\n", reg, val);
        
        // Combine value and ID, then XOR with rotation
        target_ulong combined = val;
        hash ^= combined;
        // Rotate hash for better mixing
        hash = (hash << 13) | (hash >> (64 - 13));
    }
    // printf("Final hash: 0x%lx\n", hash);
    
    return hash;
}

void HELPER(sigriscv_switch_sigmode)(CPUArchState *env, target_ulong next_pc)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    if (!is_sigriscv_use_enabled(env)) {
        return;
    }
    
    riscv_env->idcsr &= ~IDCSR_USE;
    riscv_env->idcsr |= IDCSR_UPSE;
    riscv_env->exitraw = next_pc;
    riscv_env->hashsig = sigriscv_hash_callee_regs(env);
    if (riscv_env->priv == PRV_U) {
        static const int caller_saved_regs[] = {
            1, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31
        };
        for (int i = 0; i < sizeof(caller_saved_regs) / sizeof(caller_saved_regs[0]); i++) {
            riscv_env->gpr_id[i] = 0;
        }
    }
}

void HELPER(sigriscv_check_upse_return)(CPUArchState *env, target_ulong next_pc, 
                                       void *retaddr)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    
    // Check if UPSE bit (bit 31 of idcsr) == 1
    if (!(riscv_env->idcsr & IDCSR_UPSE)) {
        return;  // Normal return, no check needed
    }
    
    // Check if next_pc == exitraw
    if (next_pc == riscv_env->exitraw) {
        // Verify hash
        target_ulong current_hash = sigriscv_hash_callee_regs(env);
        
        if (current_hash == riscv_env->hashsig) {
            // Hash matches, restore state
            riscv_env->idcsr &= ~IDCSR_UPSE;  /* Clear UPSE (bit 31) */
            riscv_env->idcsr |= IDCSR_USE;    /* Set USE (bit 30) */
        } else {
            // Hash mismatch, trigger illegal instruction exception
            riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, (uintptr_t)retaddr);
        }
    }
    // else: returning to different address, do nothing
}

target_ulong helper_sigriscv_debug(CPUArchState *env, target_ulong imm, 
                                    uint32_t rs1, uint32_t rd, void *retaddr)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    int i, j, k;
    target_ulong result = 0;
    unsigned long encmap_val;
    const char* gpr_alias[32] = {
        "x0",   "ra",  "sp",  "gp",  "tp",  "t0",  "t1",  "t2",
        "s0",   "s1",  "a0",  "a1",  "a2",  "a3",  "a4",  "a5",
        "a6",   "a7",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
        "s8",   "s9",  "s10", "s11", "t3",  "t4",  "t5",  "t6"
    };

    switch (imm) {
    case 0:
        /* imm=0: 输出所有CSR（原有功能） */
        fprintf(stderr, "=== SigRISCV Debug Info ===\n");
        
        /* Print skey */
        fprintf(stderr, "SKEY: 0x%016lx 0x%016lx\n", 
                (unsigned long)riscv_env->skey[0], 
                (unsigned long)riscv_env->skey[1]);
        
        /* Print mkey */
        fprintf(stderr, "MKEY: 0x%016lx 0x%016lx\n", 
                (unsigned long)riscv_env->mkey[0], 
                (unsigned long)riscv_env->mkey[1]);
        
        /* Print PCID */
        fprintf(stderr, "PCID: 0x%08x\n", riscv_env->pc_id);
        
        /* Print IDCSR with bit fields */
        fprintf(stderr, "IDCSR: 0x%08x (counter=%u, USE=%u, UPSE=%u)\n", 
                riscv_env->idcsr,
                riscv_env->idcsr & IDCSR_COUNTER_MASK,
                (riscv_env->idcsr & IDCSR_USE) ? 1 : 0,
                (riscv_env->idcsr & IDCSR_UPSE) ? 1 : 0);
        
        /* Print new CSRs */
        encmap_val = riscv_env->encmap;
        fprintf(stderr, "ENCMAP: 0x%016lx\n", encmap_val);
        for (i = 0; i < 32; i ++) {
            if(encmap_val & (1UL << i)) {
                fprintf(stderr, "%s ", gpr_alias[i]);
            }
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "EXITRAW: 0x%016lx\n", (unsigned long)riscv_env->exitraw);
        fprintf(stderr, "HASHSIG: 0x%016lx\n", (unsigned long)riscv_env->hashsig);
        
        /* Print all GPR IDs */
        fprintf(stderr, "GPR Val+IDs:\n");
        for (i = 0; i < 32; i+=4) {
            fprintf(stderr, "val:");
            for (j = 0; j < 4; j++ ) {
                k = i + j;
                fprintf(stderr, "  %s: 0x%016lx", gpr_alias[k], k ? env->gpr[k] : 0L);
                if (i % 4 == 3) {
                    fprintf(stderr, " ");
                }
            }
            fprintf(stderr, "\n");

            fprintf(stderr, "IDs:");
            for (j = 0; j < 4; j++ ) {
                k = i + j;
                fprintf(stderr, "  %s: 0x%016x", gpr_alias[k], riscv_env->gpr_id[k]);
                if (i % 4 == 3) {
                    fprintf(stderr, " ");
                }
            }
            fprintf(stderr, "\n");
        }
        
        fprintf(stderr, "===========================\n");
        break;

    case 1:
        /* imm=1: 以char格式输出rs1寄存器的值 */
        {
            target_ulong val = riscv_env->gpr[rs1];
            uint8_t char_val = (uint8_t)(val & 0xFF);
            if (char_val == '\n' || char_val == '\r' || char_val == '\t' || (char_val >= 32 && char_val < 127)) {
                fprintf(stderr, "%c", char_val);
            } else {
                fprintf(stderr, ".");
            }
        }
        break;

    case 2:
        /* imm=2: 以int格式输出rs1寄存器的值 */
        {
            target_ulong val = riscv_env->gpr[rs1];
            fprintf(stderr, "%ld", val);
        }
        break;

    case 3:
        /* imm=3: 输出rs1寄存器的值和gprid，将id赋给rd */
        {
            target_ulong rs1_val = riscv_env->gpr[rs1];
            target_ulong rs1_id = helper_sigriscv_get_gpr_id(env, rs1);
            fprintf(stderr, "0x%lx(id:%x)", (unsigned long)rs1_val,(uint32_t)rs1_id);
            result = rs1_id;
        }
        break;

    case 4:
        /* imm=4: 读取[rs1]作为CSR地址，输出CSR值并赋给rd */
        {
            target_ulong csr_addr = riscv_env->gpr[rs1];
            target_ulong csr_val = 0;
            
            /* 根据CSR地址读取对应的CSR值 */
            if (csr_addr >= 0x5d0 && csr_addr <= 0x5ef) {
                /* GPRID: 0x5d0-0x5ef */
                uint32_t reg_idx = csr_addr - 0x5d0;
                if (reg_idx < SIGCSR_GPRID_NUM) {
                    csr_val = riscv_env->gpr_id[reg_idx];
                }
                fprintf(stderr, "CSR[0x%lx] (GPRID[%u]) = 0x%lx\n", 
                        (unsigned long)csr_addr, reg_idx, (unsigned long)csr_val);
            } else if (csr_addr == 0x5f2) {
                /* PCID: 0x5f2 */
                csr_val = riscv_env->pc_id;
                fprintf(stderr, "CSR[0x%lx] (PCID) = 0x%lx\n", 
                        (unsigned long)csr_addr, (unsigned long)csr_val);
            } else if (csr_addr == 0x5f3) {
                /* IDCSR: 0x5f3 */
                csr_val = riscv_env->idcsr;
                fprintf(stderr, "CSR[0x%lx] (IDCSR) = 0x%lx\n", 
                        (unsigned long)csr_addr, (unsigned long)csr_val);
            } else if (csr_addr == 0x5f4) {
                /* ENCMAP: 0x5f4 */
                csr_val = riscv_env->encmap;
                fprintf(stderr, "CSR[0x%lx] (ENCMAP) = 0x%lx\n", 
                        (unsigned long)csr_addr, (unsigned long)csr_val);
                for (i = 0; i < 32; i ++) {
                    if(csr_val & (1UL << i)) {
                        fprintf(stderr, "%s ", gpr_alias[i]);
                    }
                }
        fprintf(stderr, "\n");
            } else if (csr_addr == 0x5f5) {
                /* EXITRAW: 0x5f5 */
                csr_val = riscv_env->exitraw;
                fprintf(stderr, "CSR[0x%lx] (EXITRAW) = 0x%lx\n", 
                        (unsigned long)csr_addr, (unsigned long)csr_val);
            } else if (csr_addr == 0x5f6) {
                /* HASHSIG: 0x5f6 */
                csr_val = riscv_env->hashsig;
                fprintf(stderr, "CSR[0x%lx] (HASHSIG) = 0x%lx\n", 
                        (unsigned long)csr_addr, (unsigned long)csr_val);
            } else {
                fprintf(stderr, "Unknown SigCSR address: 0x%lx\n", (unsigned long)csr_addr);
            }
            
            result = csr_val;
        }
        break;

    default:
        fprintf(stderr, "Unknown debug mode: imm=%ld\n", (long)imm);
        break;
    }
    
    return result;
 }

#endif /* TARGET_SIGRISCV */

