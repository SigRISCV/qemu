#ifdef TARGET_SIGRISCV

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

    tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
    
    return true;
}

static bool trans_setrawid(DisasContext *ctx, arg_setrawid *a)
{
    decode_save_opc(ctx, 0);

    /* In U-mode, check use bit; if not set, treat as nop */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_setdummyid = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit == 0) goto done (nop) */
        tcg_gen_brcondi_tl(TCG_COND_EQ, use_bit, 0, done);
        
        gen_set_label(do_setdummyid);
        /* Fall through to normal execution */
        
        TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
        TCGv result = tcg_temp_new();
        tcg_gen_addi_tl(result, src, a->imm);

        if (a->rd != 0) {
            gen_set_gpr(ctx, a->rd, result);
            /* Set rd.id = 0 */
            gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd),\
                ctx->zero);
        }
        
        gen_set_label(done);
        return true;
    }

    /* S/M mode: always execute */
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv result = tcg_temp_new();
    tcg_gen_addi_tl(result, src, a->imm);

    if (a->rd != 0) {
        gen_set_gpr(ctx, a->rd, result);
        /* Set rd.id = 0 */
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), ctx->zero);
    }

    return true;
}

static bool trans_setdummyid(DisasContext *ctx, arg_setdummyid *a)
{
    decode_save_opc(ctx, 0);

    /* In U-mode, check use bit; if not set, treat as nop */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_setdummyid = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit == 0) goto done (nop) */
        tcg_gen_brcondi_tl(TCG_COND_EQ, use_bit, 0, done);
        
        gen_set_label(do_setdummyid);
        /* Fall through to normal execution */
        
        TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
        TCGv result = tcg_temp_new();
        tcg_gen_addi_tl(result, src, a->imm);

        if (a->rd != 0) {
            gen_set_gpr(ctx, a->rd, result);
            /* Set rd.id = 1 */
            TCGv one_num = tcg_constant_tl(1);
            gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd),\
                one_num);
        }
        
        gen_set_label(done);
        return true;
    }

    /* S/M mode: always execute */
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv result = tcg_temp_new();
    tcg_gen_addi_tl(result, src, a->imm);

    if (a->rd != 0) {
        gen_set_gpr(ctx, a->rd, result);
        /* Set rd.id = 1 */
        TCGv one_num = tcg_constant_tl(1);
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), one_num);
    }

    return true;
}

static bool trans_setnewid(DisasContext *ctx, arg_setnewid *a)
{
    decode_save_opc(ctx, 0);

    /* In U-mode, check use bit; if not set, treat as nop */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_setnewid = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit == 0) goto done (nop) */
        tcg_gen_brcondi_tl(TCG_COND_EQ, use_bit, 0, done);
        
        gen_set_label(do_setnewid);
        /* Fall through to normal execution */
        
        TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
        TCGv result = tcg_temp_new();
        tcg_gen_addi_tl(result, src, a->imm);

        if (a->rd != 0) {
            gen_set_gpr(ctx, a->rd, result);

            /* Get current IDCSR value */
            TCGv idcsr = tcg_temp_new();
            gen_helper_sigriscv_get_idcsr(idcsr, tcg_env);

            /* Set rd.id = idcsr */
            gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), idcsr);

            /* Increment IDCSR: idcsr++ */
            TCGv new_idcsr = tcg_temp_new();
            tcg_gen_addi_tl(new_idcsr, idcsr, 1);
            gen_helper_sigriscv_set_idcsr(tcg_env, new_idcsr);
        }
        
        gen_set_label(done);
        return true;
    }

    /* S/M mode: always execute */
    TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv result = tcg_temp_new();
    tcg_gen_addi_tl(result, src, a->imm);

    if (a->rd != 0) {
        gen_set_gpr(ctx, a->rd, result);

        /* Get current IDCSR value */
        TCGv idcsr = tcg_temp_new();
        gen_helper_sigriscv_get_idcsr(idcsr, tcg_env);

        /* Set rd.id = idcsr */
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), idcsr);

        /* Increment IDCSR: idcsr++ */
        TCGv new_idcsr = tcg_temp_new();
        tcg_gen_addi_tl(new_idcsr, idcsr, 1);
        gen_helper_sigriscv_set_idcsr(tcg_env, new_idcsr);
    }

    return true;
}

static bool trans_switchs(DisasContext *ctx, arg_switchs *a)
{
    decode_save_opc(ctx, 0);

    /* In U-mode: unconditionally end TB to handle conditional PC modification
     * If USE=0, switchs becomes NOP but we still end the TB for simplicity */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit == 0) goto done (nop) */
        tcg_gen_brcondi_tl(TCG_COND_EQ, use_bit, 0, done);
        
        if (a->rs2 == 0) {
            TCGv next_pc = tcg_temp_new();
            gen_pc_plus_diff(next_pc, ctx, ctx->cur_insn_len);
            tcg_gen_st_tl(next_pc, tcg_env, offsetof(CPURISCVState, exitraw));
        } else {
            TCGv rs2_val = get_gpr(ctx, a->rs2, EXT_NONE);
            tcg_gen_st_tl(rs2_val, tcg_env, offsetof(CPURISCVState, exitraw));
        }
        
        
        TCGv hash = tcg_temp_new();
        gen_helper_sigriscv_hash_callee_regs(hash, tcg_env);
        tcg_gen_st_tl(hash, tcg_env, offsetof(CPURISCVState, hashsig));
        
        static const int caller_saved_regs[] = {
            1, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31
        };
        for (int i = 0; i < sizeof(caller_saved_regs) / sizeof(caller_saved_regs[0]); i++) {
            gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(caller_saved_regs[i]), ctx->zero);
        }
        
        TCGv idcsr = tcg_temp_new();
        tcg_gen_ld_tl(idcsr, tcg_env, offsetof(CPURISCVState, idcsr));
        tcg_gen_ori_tl(idcsr, idcsr, IDCSR_UPSE);
        tcg_gen_andi_tl(idcsr, idcsr, ~IDCSR_USE);
        tcg_gen_st_tl(idcsr, tcg_env, offsetof(CPURISCVState, idcsr));
        
        gen_set_label(done);
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

