#ifdef TARGET_SIGRISCV

static bool gen_ls_map_impl(DisasContext *ctx, int rs1, int rd, int32_t imm,
                            bool with_encmap)
{
    TCGv addr = get_address(ctx, rs1, imm);
    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
    TCGv secret = tcg_temp_new();
    tcg_gen_qemu_ld_tl(secret, addr, ctx->mem_idx, memop);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }

    TCGv_i32 rs1_idx = tcg_constant_i32(rs1);
    TCGv_i32 rd_idx = tcg_constant_i32(rd);
    TCGv decrypted = tcg_temp_new();
    if (with_encmap) {
        gen_helper_sigriscv_decrypt_setid_encmap(decrypted, tcg_env, secret,
                                                 addr, rs1_idx, rd_idx);
    } else {
        gen_helper_sigriscv_decrypt_setid(decrypted, tcg_env, secret, addr,
                                          rs1_idx, rd_idx);
    }

    if (rd != 0) {
        gen_set_gpr_restore_id(ctx, rd, decrypted);
    }

    return true;
}

static bool gen_ss_id_impl(DisasContext *ctx, int rs1, int rs2, int32_t imm,
                           bool with_encmap)
{
    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }

    TCGv addr = get_address(ctx, rs1, imm);
    TCGv src = get_gpr(ctx, rs2, EXT_NONE);

    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
        
    TCGv encrypted = tcg_temp_new();
    TCGv_i32 rs1_idx = tcg_constant_i32(rs1);
    TCGv_i32 rs2_idx = tcg_constant_i32(rs2);
    if (with_encmap) {
        gen_helper_sigriscv_encrypt_withid_encmap(encrypted, tcg_env, src,
                                                  addr, rs1_idx, rs2_idx);
    } else {
        gen_helper_sigriscv_encrypt_withid(encrypted, tcg_env, src, addr,
                                           rs1_idx, rs2_idx);
    }

    tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);

    return true;
}

static bool trans_ls(DisasContext *ctx, arg_ls *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    return gen_ls_map_impl(ctx, a->rs1, a->rd, a->imm, false);
}

static bool trans_ls_map(DisasContext *ctx, arg_ls_map *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    return gen_ls_map_impl(ctx, a->rs1, a->rd, a->imm, true);
}

static bool trans_ss(DisasContext *ctx, arg_ss *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    return gen_ss_id_impl(ctx, a->rs1, a->rs2, a->imm, false);
}

static bool trans_ss_id(DisasContext *ctx, arg_ss *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    return gen_ss_id_impl(ctx, a->rs1, a->rs2, a->imm, true);
}

static bool trans_setrawid(DisasContext *ctx, arg_setrawid *a)
{
    decode_save_opc(ctx, 0);

    bool ret = gen_arith(ctx, a, EXT_NONE, tcg_gen_add_tl, tcg_gen_add2_tl);

    if (a->rd != 0) {
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), ctx->zero);
    }

    return ret;
}

static bool trans_setdummyid(DisasContext *ctx, arg_setdummyid *a)
{
    decode_save_opc(ctx, 0);

    bool ret = gen_arith(ctx, a, EXT_NONE, tcg_gen_add_tl, tcg_gen_add2_tl);

    if (a->rd != 0) {
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), tcg_constant_tl(1));
    }

    return ret;
}

static bool trans_setnewid(DisasContext *ctx, arg_setnewid *a)
{
    decode_save_opc(ctx, 0);

    bool ret = gen_arith(ctx, a, EXT_NONE, tcg_gen_add_tl, tcg_gen_add2_tl);

    if (a->rd != 0) {
        gen_helper_sigriscv_set_gpr_newid(tcg_env, tcg_constant_i32(a->rd));
    }

    return ret;
}

static bool trans_switchs(DisasContext *ctx, arg_switchs *a)
{
    decode_save_opc(ctx, 0);
  
    if (a->rs2 == 0) {
        TCGv next_pc = tcg_temp_new();
        gen_pc_plus_diff(next_pc, ctx, ctx->cur_insn_len);
        gen_helper_sigriscv_switch_sigmode(tcg_env, next_pc);
    } else {
        TCGv next_pc = get_gpr(ctx, a->rs2, EXT_NONE);
        gen_helper_sigriscv_switch_sigmode(tcg_env, next_pc);
    }

    arg_jalr jalr_arg;
    jalr_arg.rs1 = a->rs1;
    jalr_arg.rd = a->rd;
    jalr_arg.imm = 0;

    return trans_jalr(ctx, &jalr_arg);

}

static bool trans_debug(DisasContext *ctx, arg_debug *a)
{
    decode_save_opc(ctx, 0);
    
    TCGv imm_val = tcg_constant_tl(a->imm);
    TCGv result = tcg_temp_new();
    
    gen_helper_sigriscv_debug(result, tcg_env, imm_val, 
                              tcg_constant_i32(a->rs1), 
                              tcg_constant_i32(a->rd),
                              tcg_constant_ptr(0));
    
    /* 如果rd != 0，将结果写入rd */
    if (a->rd != 0) {
        gen_set_gpr(ctx, a->rd, result);
    }
    
    return true;
}

#define SIGRISCV_S0 8
#define SIGRISCV_S1 9
#define SIGRISCV_S2 18

static int sigriscv_get_s_reg(unsigned s_idx)
{
    if (s_idx == 0) {
        return SIGRISCV_S0;
    }
    if (s_idx == 1) {
        return SIGRISCV_S1;
    }
    return SIGRISCV_S2 + (s_idx - 2);
}

static bool trans_calleesave(DisasContext *ctx, arg_calleesave *a)
{
    unsigned seq = a->rd;
    unsigned s_count = seq & 0xf;
    bool has_ra = seq & 0x10;
    int32_t cur_imm;

    if (s_count > 12 || (!has_ra && s_count == 0)) {
        return false;
    }

    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    cur_imm = a->imm + ((int32_t)has_ra + (int32_t)s_count) * 8;

    if (has_ra) {
        if (!gen_ss_id_impl(ctx, a->rs1, xRA, cur_imm, true)) {
            return false;
        }
        cur_imm -= 8;
    }

    for (unsigned i = 0; i < s_count; ++i) {
        if (!gen_ss_id_impl(ctx, a->rs1, sigriscv_get_s_reg(i), cur_imm,
                            true)) {
            return false;
        }
        cur_imm -= 8;
    }

    return gen_ss_id_impl(ctx, a->rs1, 0, a->imm, true);
}

static bool trans_calleerestore(DisasContext *ctx, arg_calleerestore *a)
{
    unsigned seq = a->rd;
    unsigned s_count = seq & 0xf;
    bool has_ra = seq & 0x10;
    int32_t cur_imm;

    if (s_count > 12 || (!has_ra && s_count == 0)) {
        return false;
    }

    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    if (!gen_ls_map_impl(ctx, a->rs1, 0, a->imm, true)) {
        return false;
    }

    cur_imm = a->imm + ((int32_t)has_ra + (int32_t)s_count) * 8;

    if (has_ra) {
        if (!gen_ls_map_impl(ctx, a->rs1, xRA, cur_imm, true)) {
            return false;
        }
        cur_imm -= 8;
    }

    for (unsigned i = 0; i < s_count; ++i) {
        if (!gen_ls_map_impl(ctx, a->rs1, sigriscv_get_s_reg(i), cur_imm,
                             true)) {
            return false;
        }
        cur_imm -= 8;
    }

    return true;
}

#endif /* TARGET_SIGRISCV */
