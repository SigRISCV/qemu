#include "qemu/osdep.h"

#ifdef TARGET_SIGRISCV

#include "cpu.h"
#include "exec/helper-proto.h"
#include "target/riscv/cpu_bits.h"
#include "qarma.h"

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

target_ulong helper_sigriscv_encrypt_ptr(CPUArchState *env,
                                         target_ulong plaintext,
                                         target_ulong tweak)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    target_ulong keyl, keyh;
    get_sigriscv_key(riscv_env, &keyl, &keyh);
    return qarma64_enc(plaintext, tweak, keyl, keyh, 7);
}

target_ulong helper_sigriscv_decrypt_ptr(CPUArchState *env,
                                         target_ulong secret,
                                         target_ulong tweak)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    target_ulong keyl, keyh;
    get_sigriscv_key(riscv_env, &keyl, &keyh);
    return qarma64_dec(secret, tweak, keyl, keyh, 7);
}

target_ulong helper_sigriscv_get_gpr_id(CPUArchState *env, uint32_t reg)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    
    if (reg >= SIGCSR_GPRID_NUM) {
        return 0;
    }

    return riscv_env->gpr_id[reg] & SIGCSR_ID_MASK;
}

void helper_sigriscv_set_gpr_id(CPUArchState *env, uint32_t reg, target_ulong id)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    
    if (reg == 0 || reg >= SIGCSR_GPRID_NUM) {
        return;
    }

    riscv_env->gpr_id[reg] = id & SIGCSR_ID_MASK;
}

target_ulong helper_sigriscv_get_idcsr(CPUArchState *env)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    return riscv_env->idcsr & SIGCSR_ID_MASK;
}

void helper_sigriscv_set_idcsr(CPUArchState *env, target_ulong id)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    riscv_env->idcsr = id & SIGCSR_ID_MASK;
}

void helper_sigriscv_debug(CPUArchState *env)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    int i;

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
    
    /* Print IDCSR */
    fprintf(stderr, "IDCSR: 0x%08x\n", riscv_env->idcsr);
    
    /* Print all GPR IDs */
    fprintf(stderr, "GPR IDs:\n");
    for (i = 0; i < 32; i++) {
        fprintf(stderr, "  x%2d: 0x%08x", i, riscv_env->gpr_id[i]);
        if (i % 4 == 3) {
            fprintf(stderr, "\n");
        } else {
            fprintf(stderr, "  ");
        }
    }
    
    fprintf(stderr, "===========================\n");
}

target_ulong helper_sigriscv_check_use_enabled(CPUArchState *env)
{
    CPURISCVState *riscv_env = (CPURISCVState *)env;
    // Check USE bit (bit 30 of idcsr) in U-mode
    if (riscv_env->priv == PRV_U) {
        return (riscv_env->idcsr & IDCSR_USE) ? 1 : 0;
    }
    // S/M mode: always enabled
    return 1;
}

target_ulong helper_sigriscv_hash_callee_regs(CPUArchState *env)
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
        target_ulong id = riscv_env->gpr_id[reg];
        
        // Combine value and ID, then XOR with rotation
        target_ulong combined = val ^ (id << 40);
        hash ^= combined;
        // Rotate hash for better mixing
        hash = (hash << 13) | (hash >> (64 - 13));
    }
    
    return hash;
}

void helper_sigriscv_check_upse_return(CPUArchState *env, target_ulong next_pc, 
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
        target_ulong current_hash = helper_sigriscv_hash_callee_regs(env);
        
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

#endif /* TARGET_SIGRISCV */

