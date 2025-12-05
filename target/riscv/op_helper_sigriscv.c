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

#endif /* TARGET_SIGRISCV */

