#ifdef TARGET_SIGRISCV

static void add_insn_cycle(DisasContext *ctx, int num)
{
    arg_addi arg;
    arg.rd = 0;
    arg.rs1 = 0;
    arg.imm = 0;
    for (int i=0;i < num; i++) {
        trans_addi(ctx, &arg);
    }
}

static bool trans_ls(DisasContext *ctx, arg_ls *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    TCGv addr = get_address(ctx, a->rs1, a->imm);
    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
    TCGv secret = tcg_temp_new();
    tcg_gen_qemu_ld_tl(secret, addr, ctx->mem_idx, memop);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }

    TCGv_i32 rs1_idx = tcg_constant_i32(a->rs1);
    TCGv_i32 rd_idx = tcg_constant_i32(a->rd);
    TCGv decrypted = tcg_temp_new();
    gen_helper_sigriscv_decrypt_setid(decrypted, tcg_env, secret, addr, rs1_idx, rd_idx);
    add_insn_cycle(ctx, 3);

    if (a->rd != 0) {
        gen_set_gpr_restore_id(ctx, a->rd, decrypted);
    }

    return true;
}

static bool trans_ls_map(DisasContext *ctx, arg_ls_map *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    TCGv addr = get_address(ctx, a->rs1, a->imm);
    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
    TCGv secret = tcg_temp_new();
    tcg_gen_qemu_ld_tl(secret, addr, ctx->mem_idx, memop);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }

    TCGv_i32 rs1_idx = tcg_constant_i32(a->rs1);
    TCGv_i32 rd_idx = tcg_constant_i32(a->rd);
    TCGv decrypted = tcg_temp_new();
    gen_helper_sigriscv_decrypt_setid_encmap(decrypted, tcg_env, secret, addr, rs1_idx, rd_idx);
    add_insn_cycle(ctx, 3);

    if (a->rd != 0) {
        gen_set_gpr_restore_id(ctx, a->rd, decrypted);
    }

    return true;
}

static bool trans_ss(DisasContext *ctx, arg_ss *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }

    TCGv addr = get_address(ctx, a->rs1, a->imm);
    TCGv src = get_gpr(ctx, a->rs2, EXT_NONE);

    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
        
    TCGv encrypted = tcg_temp_new();
    TCGv_i32 rs1_idx = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2_idx = tcg_constant_i32(a->rs2);
    gen_helper_sigriscv_encrypt_withid(encrypted, tcg_env, src, addr, rs1_idx, rs2_idx);
    add_insn_cycle(ctx, 3);

    tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
    
    return true;
}

static bool trans_ss_id(DisasContext *ctx, arg_ss *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }

    TCGv addr = get_address(ctx, a->rs1, a->imm);
    TCGv src = get_gpr(ctx, a->rs2, EXT_NONE);

    MemOp memop = MO_UQ | mo_endian(ctx);
    if (ctx->cfg_ptr->ext_zama16b) {
        memop |= MO_ATOM_WITHIN16;
    }
        
    TCGv encrypted = tcg_temp_new();
    TCGv_i32 rs1_idx = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2_idx = tcg_constant_i32(a->rs2);
    gen_helper_sigriscv_encrypt_withid_encmap(encrypted, tcg_env, src, addr, rs1_idx, rs2_idx);
    add_insn_cycle(ctx, 3);

    tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
    
    return true;
}

static bool trans_setrawid(DisasContext *ctx, arg_setrawid *a)
{
    decode_save_opc(ctx, 0);

    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv result = tcg_temp_new();
    tcg_gen_addi_tl(result, src, a->imm);

    if (a->rd != 0) {
        gen_set_gpr_restore_id(ctx, a->rd, result);
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), ctx->zero);
    }

    return true;
}

static bool trans_setdummyid(DisasContext *ctx, arg_setdummyid *a)
{
    decode_save_opc(ctx, 0);

    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv result = tcg_temp_new();
    tcg_gen_addi_tl(result, src, a->imm);

    if (a->rd != 0) {
        gen_set_gpr_restore_id(ctx, a->rd, result);
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), tcg_constant_tl(1));
    }

    return true;
}

static bool trans_setnewid(DisasContext *ctx, arg_setnewid *a)
{
    decode_save_opc(ctx, 0);

    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv result = tcg_temp_new();
    tcg_gen_addi_tl(result, src, a->imm);

    if (a->rd != 0) {
        gen_set_gpr_restore_id(ctx, a->rd, result);
        gen_helper_sigriscv_set_gpr_newid(tcg_env, tcg_constant_i32(a->rd));
    }

    return true;
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

#endif /* TARGET_SIGRISCV */

