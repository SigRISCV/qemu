#ifdef TARGET_SIGRISCV

static bool trans_ls(DisasContext *ctx, arg_ls *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    TCGv addr = get_address(ctx, a->rs1, a->imm);
    
    /* In U-mode, check use bit; if not set, degrade to normal ld */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_ls = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit != 0) goto do_ls */
        tcg_gen_brcondi_tl(TCG_COND_NE, use_bit, 0, do_ls);
        
        /* Normal ld */
        MemOp ld_memop = MO_TESQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            ld_memop |= MO_ATOM_WITHIN16;
        }
        TCGv val = tcg_temp_new();
        tcg_gen_qemu_ld_tl(val, addr, ctx->mem_idx, ld_memop);
        gen_set_gpr(ctx, a->rd, val);
        tcg_gen_br(done);
        
        /* do_ls: execute ls instruction */
        gen_set_label(do_ls);
        
        /* LS logic */
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        TCGv encrypted = tcg_temp_new();
        tcg_gen_qemu_ld_tl(encrypted, addr, ctx->mem_idx, memop);

        if (ctx->ztso) {
            tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
        }

        TCGv base_id = tcg_temp_new();
        gen_helper_sigriscv_get_gpr_id(base_id, tcg_env, tcg_constant_i32(a->rs1));

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
        
        gen_set_label(done);
    } else {
        /* S/M mode: always execute ls */
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        TCGv encrypted = tcg_temp_new();
        tcg_gen_qemu_ld_tl(encrypted, addr, ctx->mem_idx, memop);

        if (ctx->ztso) {
            tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
        }

        TCGv base_id = tcg_temp_new();
        tcg_gen_movi_tl(base_id, 0);

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

    /* In U-mode, check use bit; if not set, degrade to normal sd */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_ss = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit != 0) goto do_ss */
        tcg_gen_brcondi_tl(TCG_COND_NE, use_bit, 0, do_ss);
        
        /* Normal sd */
        MemOp sd_memop = MO_TESQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            sd_memop |= MO_ATOM_WITHIN16;
        }
        tcg_gen_qemu_st_tl(src, addr, ctx->mem_idx, sd_memop);
        tcg_gen_br(done);
        
        /* do_ss: execute ss instruction */
        gen_set_label(do_ss);
        
        /* SS logic */
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        
        TCGv value_masked = tcg_temp_new();
        tcg_gen_andi_tl(value_masked, src, SIGCSR_PTR_MASK);

        TCGv id = tcg_temp_new();
        gen_helper_sigriscv_get_gpr_id(id, tcg_env, tcg_constant_i32(a->rs2));

        TCGv id_shifted = tcg_temp_new();
        tcg_gen_shli_tl(id_shifted, id, SIGCSR_ID_SHIFT);

        TCGv plaintext = tcg_temp_new();
        tcg_gen_or_tl(plaintext, id_shifted, value_masked);

        TCGv base_id = tcg_temp_new();
        gen_helper_sigriscv_get_gpr_id(base_id, tcg_env, tcg_constant_i32(a->rs1));

        TCGv base_id_shifted = tcg_temp_new();
        tcg_gen_shli_tl(base_id_shifted, base_id, SIGCSR_ID_SHIFT);

        TCGv addr_lower = tcg_temp_new();
        tcg_gen_andi_tl(addr_lower, addr, SIGCSR_PTR_MASK);

        TCGv tweak = tcg_temp_new();
        tcg_gen_or_tl(tweak, base_id_shifted, addr_lower);

        TCGv encrypted = tcg_temp_new();
        gen_helper_sigriscv_encrypt_ptr(encrypted, tcg_env, plaintext, tweak);

        tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
        
        gen_set_label(done);
    } else {
        /* S/M mode: always execute ss with ID=0 */
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        
        TCGv value_masked = tcg_temp_new();
        tcg_gen_andi_tl(value_masked, src, SIGCSR_PTR_MASK);

        TCGv id = tcg_temp_new();
        tcg_gen_movi_tl(id, 0);  /* S/M mode uses ID=0 */

        TCGv id_shifted = tcg_temp_new();
        tcg_gen_shli_tl(id_shifted, id, SIGCSR_ID_SHIFT);

        TCGv plaintext = tcg_temp_new();
        tcg_gen_or_tl(plaintext, id_shifted, value_masked);

        TCGv base_id = tcg_temp_new();
        tcg_gen_movi_tl(base_id, 0);  /* S/M mode uses ID=0 */

        TCGv base_id_shifted = tcg_temp_new();
        tcg_gen_shli_tl(base_id_shifted, base_id, SIGCSR_ID_SHIFT);

        TCGv addr_lower = tcg_temp_new();
        tcg_gen_andi_tl(addr_lower, addr, SIGCSR_PTR_MASK);

        TCGv tweak = tcg_temp_new();
        tcg_gen_or_tl(tweak, base_id_shifted, addr_lower);

        TCGv encrypted = tcg_temp_new();
        gen_helper_sigriscv_encrypt_ptr(encrypted, tcg_env, plaintext, tweak);

        tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
    }
    
    return true;
}

static bool trans_setrawid(DisasContext *ctx, arg_setrawid *a)
{
    decode_save_opc(ctx, 0);

    /* In U-mode, check use bit; if not set, treat as nop */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_setrawid = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit == 0) goto done (nop) */
        tcg_gen_brcondi_tl(TCG_COND_EQ, use_bit, 0, done);
        
        gen_set_label(do_setrawid);
        /* Fall through to normal execution */
        
        TCGv src = get_gpr(ctx, a->rs1, EXT_NONE);
        TCGv result = tcg_temp_new();
        tcg_gen_addi_tl(result, src, a->imm);

        if (a->rd != 0) {
            gen_set_gpr(ctx, a->rd, result);
            /* Set rd.id = 0 */
            gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), ctx->zero);
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

static bool trans_ls_map(DisasContext *ctx, arg_ls_map *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    TCGv addr = get_address(ctx, a->rs1, a->imm);

    /* In U-mode, check use bit; if not set, degrade to normal ld */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_ls_map = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit != 0) goto do_ls_map */
        tcg_gen_brcondi_tl(TCG_COND_NE, use_bit, 0, do_ls_map);
        
        /* Normal ld (regardless of rd value) */
        MemOp ld_memop = MO_TESQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            ld_memop |= MO_ATOM_WITHIN16;
        }
        TCGv val = tcg_temp_new();
        tcg_gen_qemu_ld_tl(val, addr, ctx->mem_idx, ld_memop);
        if (a->rd != 0) {
            gen_set_gpr(ctx, a->rd, val);
        }
        tcg_gen_br(done);
        
        gen_set_label(do_ls_map);
        /* ls_map logic for U-mode */

        if (a->rd == 0) {
            /* ls.encmap: load encmap from memory */
            MemOp memop = MO_UQ | mo_endian(ctx);
            if (ctx->cfg_ptr->ext_zama16b) {
                memop |= MO_ATOM_WITHIN16;
            }
            TCGv encmap_val = tcg_temp_new();
            tcg_gen_qemu_ld_tl(encmap_val, addr, ctx->mem_idx, memop);
            tcg_gen_st_tl(encmap_val, tcg_env, offsetof(CPURISCVState, encmap));
        } else {
            /* Check encmap bit for rd */
            TCGv encmap = tcg_temp_new();
            tcg_gen_ld_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
            
            TCGv bit_mask = tcg_temp_new();
            tcg_gen_movi_tl(bit_mask, 1ULL << a->rd);
            
            TCGv bit_set = tcg_temp_new();
            tcg_gen_and_tl(bit_set, encmap, bit_mask);
            
            TCGLabel *label_ld = gen_new_label();
            TCGLabel *label_done = gen_new_label();
            
            /* if ((encmap >> rd) & 1) == 0, jump to normal ld */
            tcg_gen_brcondi_tl(TCG_COND_EQ, bit_set, 0, label_ld);
            
            /* Execute ls rd, imm(rs1) */
            MemOp memop = MO_UQ | mo_endian(ctx);
            if (ctx->cfg_ptr->ext_zama16b) {
                memop |= MO_ATOM_WITHIN16;
            }
            TCGv encrypted = tcg_temp_new();
            tcg_gen_qemu_ld_tl(encrypted, addr, ctx->mem_idx, memop);
            
            if (ctx->ztso) {
                tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
            }
            
            TCGv base_id = tcg_temp_new();
            gen_helper_sigriscv_get_gpr_id(base_id, tcg_env, tcg_constant_i32(a->rs1));
            
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
            gen_set_gpr(ctx, a->rd, pointer);
            
            TCGv id = tcg_temp_new();
            tcg_gen_shri_tl(id, decrypted, SIGCSR_ID_SHIFT);
            tcg_gen_andi_tl(id, id, SIGCSR_ID_MASK);
            gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), id);
            
            /* encmap ^= 1<<rd */
            tcg_gen_xor_tl(encmap, encmap, bit_mask);
            tcg_gen_st_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
            
            tcg_gen_br(label_done);
            
            /* Normal ld */
            gen_set_label(label_ld);
            memop = MO_TESQ | mo_endian(ctx);
            if (ctx->cfg_ptr->ext_zama16b) {
                memop |= MO_ATOM_WITHIN16;
            }
            TCGv val_ld = tcg_temp_new();
            tcg_gen_qemu_ld_tl(val_ld, addr, ctx->mem_idx, memop);
            gen_set_gpr(ctx, a->rd, val_ld);
            
            /* Clear ID */
            gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), ctx->zero);
            
            gen_set_label(label_done);
        }
        
        gen_set_label(done);
        return true;
    }
    
    /* S/M mode: always execute ls_map */
    if (a->rd == 0) {
        /* ls.encmap: load encmap from memory */
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        TCGv encmap_val = tcg_temp_new();
        tcg_gen_qemu_ld_tl(encmap_val, addr, ctx->mem_idx, memop);
        tcg_gen_st_tl(encmap_val, tcg_env, offsetof(CPURISCVState, encmap));
    } else {
        /* Check encmap bit for rd */
        TCGv encmap = tcg_temp_new();
        tcg_gen_ld_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
        
        TCGv bit_mask = tcg_temp_new();
        tcg_gen_movi_tl(bit_mask, 1ULL << a->rd);
        
        TCGv bit_set = tcg_temp_new();
        tcg_gen_and_tl(bit_set, encmap, bit_mask);
        
        TCGLabel *label_ld = gen_new_label();
        TCGLabel *label_done = gen_new_label();
        
        /* if ((encmap >> rd) & 1) == 0, jump to normal ld */
        tcg_gen_brcondi_tl(TCG_COND_EQ, bit_set, 0, label_ld);
        
        /* Execute ls rd, imm(rs1) */
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        TCGv encrypted = tcg_temp_new();
        tcg_gen_qemu_ld_tl(encrypted, addr, ctx->mem_idx, memop);
        
        if (ctx->ztso) {
            tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
        }
        
        TCGv base_id = tcg_temp_new();
        tcg_gen_movi_tl(base_id, 0);  /* S/M mode uses ID=0 */
        
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
        gen_set_gpr(ctx, a->rd, pointer);
        
        TCGv id = tcg_temp_new();
        tcg_gen_shri_tl(id, decrypted, SIGCSR_ID_SHIFT);
        tcg_gen_andi_tl(id, id, SIGCSR_ID_MASK);
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), id);
        
        /* encmap ^= 1<<rd */
        tcg_gen_xor_tl(encmap, encmap, bit_mask);
        tcg_gen_st_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
        
        tcg_gen_br(label_done);
        
        /* Normal ld */
        gen_set_label(label_ld);
        memop = MO_TESQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        TCGv val = tcg_temp_new();
        tcg_gen_qemu_ld_tl(val, addr, ctx->mem_idx, memop);
        gen_set_gpr(ctx, a->rd, val);
        
        /* Clear ID */
        gen_helper_sigriscv_set_gpr_id(tcg_env, tcg_constant_i32(a->rd), ctx->zero);
        
        gen_set_label(label_done);
    }
    
    return true;
}

static bool trans_ss_id(DisasContext *ctx, arg_ss_id *a)
{
    REQUIRE_64_OR_128BIT(ctx);
    decode_save_opc(ctx, 0);

    if (ctx->ztso) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }

    TCGv addr = get_address(ctx, a->rs1, a->imm);

    /* In U-mode, check use bit; if not set, degrade to normal sd */
    if (ctx->priv == PRV_U) {
        TCGv use_bit = tcg_temp_new();
        gen_helper_sigriscv_check_use_enabled(use_bit, tcg_env);
        
        TCGLabel *do_ss_id = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit != 0) goto do_ss_id */
        tcg_gen_brcondi_tl(TCG_COND_NE, use_bit, 0, do_ss_id);
        
        /* Normal sd (regardless of rs2 value) */
        MemOp sd_memop = MO_TESQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            sd_memop |= MO_ATOM_WITHIN16;
        }
        TCGv src = get_gpr(ctx, a->rs2, EXT_NONE);
        tcg_gen_qemu_st_tl(src, addr, ctx->mem_idx, sd_memop);
        tcg_gen_br(done);
        
        gen_set_label(do_ss_id);
        /* ss.id logic for U-mode */

        if (a->rs2 == 0) {
            /* ss.encmap: store encmap to memory */
            MemOp memop = MO_UQ | mo_endian(ctx);
            if (ctx->cfg_ptr->ext_zama16b) {
                memop |= MO_ATOM_WITHIN16;
            }
            TCGv encmap = tcg_temp_new();
            tcg_gen_ld_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
            tcg_gen_qemu_st_tl(encmap, addr, ctx->mem_idx, memop);
        } else {
            /* Check if rs2 has ID */
            TCGv id = tcg_temp_new();
            gen_helper_sigriscv_get_gpr_id(id, tcg_env, tcg_constant_i32(a->rs2));
            
            TCGLabel *label_sd = gen_new_label();
            TCGLabel *label_done = gen_new_label();
            
            /* if (id[rs2] == 0), jump to normal sd */
            tcg_gen_brcondi_tl(TCG_COND_EQ, id, 0, label_sd);
            
            /* Execute ss rs2, imm(rs1) */
            TCGv src_sm = get_gpr(ctx, a->rs2, EXT_NONE);
            TCGv value_masked = tcg_temp_new();
            tcg_gen_andi_tl(value_masked, src_sm, SIGCSR_PTR_MASK);
            
            TCGv id_shifted = tcg_temp_new();
            tcg_gen_shli_tl(id_shifted, id, SIGCSR_ID_SHIFT);
            
            TCGv plaintext = tcg_temp_new();
            tcg_gen_or_tl(plaintext, id_shifted, value_masked);
            
            TCGv base_id = tcg_temp_new();
            gen_helper_sigriscv_get_gpr_id(base_id, tcg_env, tcg_constant_i32(a->rs1));
            
            TCGv base_id_shifted = tcg_temp_new();
            tcg_gen_shli_tl(base_id_shifted, base_id, SIGCSR_ID_SHIFT);
            
            TCGv addr_lower = tcg_temp_new();
            tcg_gen_andi_tl(addr_lower, addr, SIGCSR_PTR_MASK);
            
            TCGv tweak = tcg_temp_new();
            tcg_gen_or_tl(tweak, base_id_shifted, addr_lower);
            
            TCGv encrypted = tcg_temp_new();
            gen_helper_sigriscv_encrypt_ptr(encrypted, tcg_env, plaintext, tweak);
            
            MemOp memop = MO_UQ | mo_endian(ctx);
            if (ctx->cfg_ptr->ext_zama16b) {
                memop |= MO_ATOM_WITHIN16;
            }
            tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
            
            /* encmap |= 1<<rs2 */
            TCGv encmap = tcg_temp_new();
            tcg_gen_ld_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
            TCGv bit_mask = tcg_temp_new();
            tcg_gen_movi_tl(bit_mask, 1ULL << a->rs2);
            tcg_gen_or_tl(encmap, encmap, bit_mask);
            tcg_gen_st_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
            
            tcg_gen_br(label_done);
            
            /* Normal sd */
            gen_set_label(label_sd);
            TCGv val = get_gpr(ctx, a->rs2, EXT_NONE);
            memop = MO_TESQ | mo_endian(ctx);
            if (ctx->cfg_ptr->ext_zama16b) {
                memop |= MO_ATOM_WITHIN16;
            }
            tcg_gen_qemu_st_tl(val, addr, ctx->mem_idx, memop);
            
            gen_set_label(label_done);
        }
        
        gen_set_label(done);
        return true;
    }
    
    /* S/M mode: always execute ss.id with ID=0 */
    if (a->rs2 == 0) {
        /* ss.encmap: store encmap to memory */
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        TCGv encmap = tcg_temp_new();
        tcg_gen_ld_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
        tcg_gen_qemu_st_tl(encmap, addr, ctx->mem_idx, memop);
    } else {
        /* Check if rs2 has ID (but will use 0 for encryption in S/M mode) */
        TCGv id = tcg_temp_new();
        tcg_gen_movi_tl(id, 0);  /* S/M mode always uses ID=0 */
        
        TCGLabel *label_sd = gen_new_label();
        TCGLabel *label_done = gen_new_label();
        
        /* Get actual rs2.id to check if we should encrypt */
        TCGv actual_id = tcg_temp_new();
        gen_helper_sigriscv_get_gpr_id(actual_id, tcg_env, tcg_constant_i32(a->rs2));
        
        /* if (actual_id == 0), jump to normal sd */
        tcg_gen_brcondi_tl(TCG_COND_EQ, actual_id, 0, label_sd);
        
        /* Execute ss rs2, imm(rs1) with ID=0 */
        TCGv src = get_gpr(ctx, a->rs2, EXT_NONE);
        TCGv value_masked = tcg_temp_new();
        tcg_gen_andi_tl(value_masked, src, SIGCSR_PTR_MASK);
        
        TCGv id_shifted = tcg_temp_new();
        tcg_gen_shli_tl(id_shifted, actual_id, SIGCSR_ID_SHIFT);
        
        TCGv plaintext = tcg_temp_new();
        tcg_gen_or_tl(plaintext, id_shifted, value_masked);
        
        TCGv base_id = tcg_temp_new();
        tcg_gen_movi_tl(base_id, 0);  /* S/M mode uses ID=0 for tweak */
        
        TCGv base_id_shifted = tcg_temp_new();
        tcg_gen_shli_tl(base_id_shifted, base_id, SIGCSR_ID_SHIFT);
        
        TCGv addr_lower = tcg_temp_new();
        tcg_gen_andi_tl(addr_lower, addr, SIGCSR_PTR_MASK);
        
        TCGv tweak = tcg_temp_new();
        tcg_gen_or_tl(tweak, base_id_shifted, addr_lower);
        
        TCGv encrypted = tcg_temp_new();
        gen_helper_sigriscv_encrypt_ptr(encrypted, tcg_env, plaintext, tweak);
        
        MemOp memop = MO_UQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        tcg_gen_qemu_st_tl(encrypted, addr, ctx->mem_idx, memop);
        
        /* encmap |= 1<<rs2 */
        TCGv encmap = tcg_temp_new();
        tcg_gen_ld_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
        TCGv bit_mask = tcg_temp_new();
        tcg_gen_movi_tl(bit_mask, 1ULL << a->rs2);
        tcg_gen_or_tl(encmap, encmap, bit_mask);
        tcg_gen_st_tl(encmap, tcg_env, offsetof(CPURISCVState, encmap));
        
        tcg_gen_br(label_done);
        
        /* Normal sd */
        gen_set_label(label_sd);
        TCGv val_sd = get_gpr(ctx, a->rs2, EXT_NONE);
        memop = MO_TESQ | mo_endian(ctx);
        if (ctx->cfg_ptr->ext_zama16b) {
            memop |= MO_ATOM_WITHIN16;
        }
        tcg_gen_qemu_st_tl(val_sd, addr, ctx->mem_idx, memop);
        
        gen_set_label(label_done);
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
        
        TCGLabel *do_switchs = gen_new_label();
        TCGLabel *done = gen_new_label();
        
        /* if (use_bit == 0) goto done (nop) */
        tcg_gen_brcondi_tl(TCG_COND_EQ, use_bit, 0, done);
        
        gen_set_label(do_switchs);
        /* Generate switchs implementation */
        
        TCGv next_pc = tcg_temp_new();
        gen_pc_plus_diff(next_pc, ctx, 4);
        gen_set_gpr(ctx, a->rd, next_pc);
        
        TCGv exitraw_val = tcg_temp_new();
        if (a->rs2 == 0) {
            tcg_gen_mov_tl(exitraw_val, next_pc);
        } else {
            TCGv rs2_val = get_gpr(ctx, a->rs2, EXT_NONE);
            tcg_gen_mov_tl(exitraw_val, rs2_val);
        }
        tcg_gen_st_tl(exitraw_val, tcg_env, offsetof(CPURISCVState, exitraw));
        
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
        
        if (a->rs1 == 0) {
            tcg_gen_mov_tl(cpu_pc, next_pc);
        } else {
            TCGv target = get_gpr(ctx, a->rs1, EXT_NONE);
            tcg_gen_mov_tl(cpu_pc, target);
        }
        
        lookup_and_goto_ptr(ctx);
        
        /* NOP path: update PC to next instruction and continue */
        gen_set_label(done);
        gen_update_pc(ctx, ctx->cur_insn_len);
        tcg_gen_exit_tb(NULL, 0);
        
        ctx->base.is_jmp = DISAS_NORETURN;
        return true;
    }

    /* S/M mode: always execute */
    TCGv next_pc = tcg_temp_new();
    gen_pc_plus_diff(next_pc, ctx, 4);
    gen_set_gpr(ctx, a->rd, next_pc);
    
    TCGv exitraw_val = tcg_temp_new();
    if (a->rs2 == 0) {
        tcg_gen_mov_tl(exitraw_val, next_pc);
    } else {
        TCGv rs2_val = get_gpr(ctx, a->rs2, EXT_NONE);
        tcg_gen_mov_tl(exitraw_val, rs2_val);
    }
    tcg_gen_st_tl(exitraw_val, tcg_env, offsetof(CPURISCVState, exitraw));
    
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
    
    if (a->rs1 == 0) {
        tcg_gen_mov_tl(cpu_pc, next_pc);
    } else {
        TCGv target = get_gpr(ctx, a->rs1, EXT_NONE);
        tcg_gen_mov_tl(cpu_pc, target);
    }
    
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
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

