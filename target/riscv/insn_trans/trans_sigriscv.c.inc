#ifdef TARGET_SIGRISCV

static bool trans_ls(DisasContext *ctx, arg_ls *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
    decode_save_opc(ctx, 0);

    TCGv addr = get_address(ctx, a->rs1, a->imm);
    TCGv encrypted = tcg_temp_new();
    tcg_gen_qemu_ld_tl(encrypted, addr, ctx->mem_idx, memop);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }

    TCGv base_id = tcg_temp_new();
    /* In S/M mode, use 0 for ID in tweak; in U mode, use actual GPR ID */
    if (ctx->priv == PRV_U) {
        gen_helper_sigriscv_get_gpr_id(base_id, tcg_env, tcg_constant_i32(a->rs1));
    } else {
        tcg_gen_movi_tl(base_id, 0);
    }

    TCGv addr_lower = tcg_temp_new();
    tcg_gen_andi_tl(addr_lower, addr, SIGCSR_PTR_MASK);

    TCGv base_id_shifted = tcg_temp_new();
    tcg_gen_shli_tl(base_id_shifted, base_id, SIGCSR_ID_SHIFT);

    TCGv tweak = tcg_temp_new();
    tcg_gen_or_tl(tweak, base_id_shifted, addr_lower);

    TCGv decrypted = tcg_temp_new();
    gen_helper_sigriscv_decrypt_ptr(decrypted, tcg_env, encrypted, tweak);

    TCGv pointer = tcg_temp_new();
    tcg_gen_andi_tl(pointer, decrypted, SIGCSR_PTR_MASK);

    if (a->rd != 0) {
        gen_set_gpr(ctx, a->rd, pointer);

        TCGv id = tcg_temp_new();
        tcg_gen_shri_tl(id, decrypted, SIGCSR_ID_SHIFT);
        tcg_gen_andi_tl(id, id, SIGCSR_ID_MASK);
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), id);
    }

    return true;
}

static bool trans_ss(DisasContext *ctx, arg_ss *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
    decode_save_opc(ctx, 0);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }

    TCGv addr = get_address(ctx, a->rs1, a->imm);
    TCGv src = get_gpr(ctx, a->rs2, EXT_NONE);

    TCGv value_masked = tcg_temp_new();
    tcg_gen_andi_tl(value_masked, src, SIGCSR_PTR_MASK);

    TCGv id = tcg_temp_new();
    /* In S/M mode, use 0 for ID in plaintext; in U mode, use actual GPR ID */
    if (ctx->priv == PRV_U) {
        gen_helper_sigriscv_get_gpr_id(id, tcg_env, tcg_constant_i32(a->rs2));
    } else {
        tcg_gen_movi_tl(id, 0);
    }

    TCGv id_shifted = tcg_temp_new();
    tcg_gen_shli_tl(id_shifted, id, SIGCSR_ID_SHIFT);

    TCGv plaintext = tcg_temp_new();
    tcg_gen_or_tl(plaintext, id_shifted, value_masked);

    TCGv base_id = tcg_temp_new();
    /* In S/M mode, use 0 for ID in tweak; in U mode, use actual GPR ID */
    if (ctx->priv == PRV_U) {
        gen_helper_sigriscv_get_gpr_id(base_id, tcg_env, tcg_constant_i32(a->rs1));
    } else {
        tcg_gen_movi_tl(base_id, 0);
    }

    TCGv base_id_shifted = tcg_temp_new();
    tcg_gen_shli_tl(base_id_shifted, base_id, SIGCSR_ID_SHIFT);

    TCGv addr_lower = tcg_temp_new();
    tcg_gen_andi_tl(addr_lower, addr, SIGCSR_PTR_MASK);

    TCGv tweak = tcg_temp_new();
    tcg_gen_or_tl(tweak, base_id_shifted, addr_lower);

    TCGv encrypted = tcg_temp_new();
    gen_helper_sigriscv_encrypt_ptr(encrypted, tcg_env, plaintext, tweak);

    tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
    return true;
}

#endif /* TARGET_SIGRISCV */

