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

#endif /* TARGET_SIGRISCV */

