/* Instruction opcode header for sh.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2017 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, see <http://www.gnu.org/licenses/>.

*/

#ifndef SH_OPC_H
#define SH_OPC_H

/* Enum declaration for sh instruction types.  */
typedef enum cgen_insn_type {
  SH_INSN_INVALID, SH_INSN_ADD_COMPACT, SH_INSN_ADDI_COMPACT, SH_INSN_ADDC_COMPACT
 , SH_INSN_ADDV_COMPACT, SH_INSN_AND_COMPACT, SH_INSN_ANDI_COMPACT, SH_INSN_ANDB_COMPACT
 , SH_INSN_BF_COMPACT, SH_INSN_BFS_COMPACT, SH_INSN_BRA_COMPACT, SH_INSN_BRAF_COMPACT
 , SH_INSN_BRK_COMPACT, SH_INSN_BSR_COMPACT, SH_INSN_BSRF_COMPACT, SH_INSN_BT_COMPACT
 , SH_INSN_BTS_COMPACT, SH_INSN_CLRMAC_COMPACT, SH_INSN_CLRS_COMPACT, SH_INSN_CLRT_COMPACT
 , SH_INSN_CMPEQ_COMPACT, SH_INSN_CMPEQI_COMPACT, SH_INSN_CMPGE_COMPACT, SH_INSN_CMPGT_COMPACT
 , SH_INSN_CMPHI_COMPACT, SH_INSN_CMPHS_COMPACT, SH_INSN_CMPPL_COMPACT, SH_INSN_CMPPZ_COMPACT
 , SH_INSN_CMPSTR_COMPACT, SH_INSN_DIV0S_COMPACT, SH_INSN_DIV0U_COMPACT, SH_INSN_DIV1_COMPACT
 , SH_INSN_DIVU_COMPACT, SH_INSN_MULR_COMPACT, SH_INSN_DMULSL_COMPACT, SH_INSN_DMULUL_COMPACT
 , SH_INSN_DT_COMPACT, SH_INSN_EXTSB_COMPACT, SH_INSN_EXTSW_COMPACT, SH_INSN_EXTUB_COMPACT
 , SH_INSN_EXTUW_COMPACT, SH_INSN_FABS_COMPACT, SH_INSN_FADD_COMPACT, SH_INSN_FCMPEQ_COMPACT
 , SH_INSN_FCMPGT_COMPACT, SH_INSN_FCNVDS_COMPACT, SH_INSN_FCNVSD_COMPACT, SH_INSN_FDIV_COMPACT
 , SH_INSN_FIPR_COMPACT, SH_INSN_FLDS_COMPACT, SH_INSN_FLDI0_COMPACT, SH_INSN_FLDI1_COMPACT
 , SH_INSN_FLOAT_COMPACT, SH_INSN_FMAC_COMPACT, SH_INSN_FMOV1_COMPACT, SH_INSN_FMOV2_COMPACT
 , SH_INSN_FMOV3_COMPACT, SH_INSN_FMOV4_COMPACT, SH_INSN_FMOV5_COMPACT, SH_INSN_FMOV6_COMPACT
 , SH_INSN_FMOV7_COMPACT, SH_INSN_FMOV8_COMPACT, SH_INSN_FMOV9_COMPACT, SH_INSN_FMUL_COMPACT
 , SH_INSN_FNEG_COMPACT, SH_INSN_FRCHG_COMPACT, SH_INSN_FSCHG_COMPACT, SH_INSN_FSQRT_COMPACT
 , SH_INSN_FSTS_COMPACT, SH_INSN_FSUB_COMPACT, SH_INSN_FTRC_COMPACT, SH_INSN_FTRV_COMPACT
 , SH_INSN_JMP_COMPACT, SH_INSN_JSR_COMPACT, SH_INSN_LDC_GBR_COMPACT, SH_INSN_LDC_VBR_COMPACT
 , SH_INSN_LDC_SR_COMPACT, SH_INSN_LDCL_GBR_COMPACT, SH_INSN_LDCL_VBR_COMPACT, SH_INSN_LDS_FPSCR_COMPACT
 , SH_INSN_LDSL_FPSCR_COMPACT, SH_INSN_LDS_FPUL_COMPACT, SH_INSN_LDSL_FPUL_COMPACT, SH_INSN_LDS_MACH_COMPACT
 , SH_INSN_LDSL_MACH_COMPACT, SH_INSN_LDS_MACL_COMPACT, SH_INSN_LDSL_MACL_COMPACT, SH_INSN_LDS_PR_COMPACT
 , SH_INSN_LDSL_PR_COMPACT, SH_INSN_MACL_COMPACT, SH_INSN_MACW_COMPACT, SH_INSN_MOV_COMPACT
 , SH_INSN_MOVI_COMPACT, SH_INSN_MOVI20_COMPACT, SH_INSN_MOVB1_COMPACT, SH_INSN_MOVB2_COMPACT
 , SH_INSN_MOVB3_COMPACT, SH_INSN_MOVB4_COMPACT, SH_INSN_MOVB5_COMPACT, SH_INSN_MOVB6_COMPACT
 , SH_INSN_MOVB7_COMPACT, SH_INSN_MOVB8_COMPACT, SH_INSN_MOVB9_COMPACT, SH_INSN_MOVB10_COMPACT
 , SH_INSN_MOVL1_COMPACT, SH_INSN_MOVL2_COMPACT, SH_INSN_MOVL3_COMPACT, SH_INSN_MOVL4_COMPACT
 , SH_INSN_MOVL5_COMPACT, SH_INSN_MOVL6_COMPACT, SH_INSN_MOVL7_COMPACT, SH_INSN_MOVL8_COMPACT
 , SH_INSN_MOVL9_COMPACT, SH_INSN_MOVL10_COMPACT, SH_INSN_MOVL11_COMPACT, SH_INSN_MOVL12_COMPACT
 , SH_INSN_MOVL13_COMPACT, SH_INSN_MOVW1_COMPACT, SH_INSN_MOVW2_COMPACT, SH_INSN_MOVW3_COMPACT
 , SH_INSN_MOVW4_COMPACT, SH_INSN_MOVW5_COMPACT, SH_INSN_MOVW6_COMPACT, SH_INSN_MOVW7_COMPACT
 , SH_INSN_MOVW8_COMPACT, SH_INSN_MOVW9_COMPACT, SH_INSN_MOVW10_COMPACT, SH_INSN_MOVW11_COMPACT
 , SH_INSN_MOVA_COMPACT, SH_INSN_MOVCAL_COMPACT, SH_INSN_MOVCOL_COMPACT, SH_INSN_MOVT_COMPACT
 , SH_INSN_MOVUAL_COMPACT, SH_INSN_MOVUAL2_COMPACT, SH_INSN_MULL_COMPACT, SH_INSN_MULSW_COMPACT
 , SH_INSN_MULUW_COMPACT, SH_INSN_NEG_COMPACT, SH_INSN_NEGC_COMPACT, SH_INSN_NOP_COMPACT
 , SH_INSN_NOT_COMPACT, SH_INSN_OCBI_COMPACT, SH_INSN_OCBP_COMPACT, SH_INSN_OCBWB_COMPACT
 , SH_INSN_OR_COMPACT, SH_INSN_ORI_COMPACT, SH_INSN_ORB_COMPACT, SH_INSN_PREF_COMPACT
 , SH_INSN_ROTCL_COMPACT, SH_INSN_ROTCR_COMPACT, SH_INSN_ROTL_COMPACT, SH_INSN_ROTR_COMPACT
 , SH_INSN_RTS_COMPACT, SH_INSN_SETS_COMPACT, SH_INSN_SETT_COMPACT, SH_INSN_SHAD_COMPACT
 , SH_INSN_SHAL_COMPACT, SH_INSN_SHAR_COMPACT, SH_INSN_SHLD_COMPACT, SH_INSN_SHLL_COMPACT
 , SH_INSN_SHLL2_COMPACT, SH_INSN_SHLL8_COMPACT, SH_INSN_SHLL16_COMPACT, SH_INSN_SHLR_COMPACT
 , SH_INSN_SHLR2_COMPACT, SH_INSN_SHLR8_COMPACT, SH_INSN_SHLR16_COMPACT, SH_INSN_STC_GBR_COMPACT
 , SH_INSN_STC_VBR_COMPACT, SH_INSN_STCL_GBR_COMPACT, SH_INSN_STCL_VBR_COMPACT, SH_INSN_STS_FPSCR_COMPACT
 , SH_INSN_STSL_FPSCR_COMPACT, SH_INSN_STS_FPUL_COMPACT, SH_INSN_STSL_FPUL_COMPACT, SH_INSN_STS_MACH_COMPACT
 , SH_INSN_STSL_MACH_COMPACT, SH_INSN_STS_MACL_COMPACT, SH_INSN_STSL_MACL_COMPACT, SH_INSN_STS_PR_COMPACT
 , SH_INSN_STSL_PR_COMPACT, SH_INSN_SUB_COMPACT, SH_INSN_SUBC_COMPACT, SH_INSN_SUBV_COMPACT
 , SH_INSN_SWAPB_COMPACT, SH_INSN_SWAPW_COMPACT, SH_INSN_TASB_COMPACT, SH_INSN_TRAPA_COMPACT
 , SH_INSN_TST_COMPACT, SH_INSN_TSTI_COMPACT, SH_INSN_TSTB_COMPACT, SH_INSN_XOR_COMPACT
 , SH_INSN_XORI_COMPACT, SH_INSN_XORB_COMPACT, SH_INSN_XTRCT_COMPACT, SH_INSN_ADD
 , SH_INSN_ADDL, SH_INSN_ADDI, SH_INSN_ADDIL, SH_INSN_ADDZL
 , SH_INSN_ALLOCO, SH_INSN_AND, SH_INSN_ANDC, SH_INSN_ANDI
 , SH_INSN_BEQ, SH_INSN_BEQI, SH_INSN_BGE, SH_INSN_BGEU
 , SH_INSN_BGT, SH_INSN_BGTU, SH_INSN_BLINK, SH_INSN_BNE
 , SH_INSN_BNEI, SH_INSN_BRK, SH_INSN_BYTEREV, SH_INSN_CMPEQ
 , SH_INSN_CMPGT, SH_INSN_CMPGTU, SH_INSN_CMVEQ, SH_INSN_CMVNE
 , SH_INSN_FABSD, SH_INSN_FABSS, SH_INSN_FADDD, SH_INSN_FADDS
 , SH_INSN_FCMPEQD, SH_INSN_FCMPEQS, SH_INSN_FCMPGED, SH_INSN_FCMPGES
 , SH_INSN_FCMPGTD, SH_INSN_FCMPGTS, SH_INSN_FCMPUND, SH_INSN_FCMPUNS
 , SH_INSN_FCNVDS, SH_INSN_FCNVSD, SH_INSN_FDIVD, SH_INSN_FDIVS
 , SH_INSN_FGETSCR, SH_INSN_FIPRS, SH_INSN_FLDD, SH_INSN_FLDP
 , SH_INSN_FLDS, SH_INSN_FLDXD, SH_INSN_FLDXP, SH_INSN_FLDXS
 , SH_INSN_FLOATLD, SH_INSN_FLOATLS, SH_INSN_FLOATQD, SH_INSN_FLOATQS
 , SH_INSN_FMACS, SH_INSN_FMOVD, SH_INSN_FMOVDQ, SH_INSN_FMOVLS
 , SH_INSN_FMOVQD, SH_INSN_FMOVS, SH_INSN_FMOVSL, SH_INSN_FMULD
 , SH_INSN_FMULS, SH_INSN_FNEGD, SH_INSN_FNEGS, SH_INSN_FPUTSCR
 , SH_INSN_FSQRTD, SH_INSN_FSQRTS, SH_INSN_FSTD, SH_INSN_FSTP
 , SH_INSN_FSTS, SH_INSN_FSTXD, SH_INSN_FSTXP, SH_INSN_FSTXS
 , SH_INSN_FSUBD, SH_INSN_FSUBS, SH_INSN_FTRCDL, SH_INSN_FTRCSL
 , SH_INSN_FTRCDQ, SH_INSN_FTRCSQ, SH_INSN_FTRVS, SH_INSN_GETCFG
 , SH_INSN_GETCON, SH_INSN_GETTR, SH_INSN_ICBI, SH_INSN_LDB
 , SH_INSN_LDL, SH_INSN_LDQ, SH_INSN_LDUB, SH_INSN_LDUW
 , SH_INSN_LDW, SH_INSN_LDHIL, SH_INSN_LDHIQ, SH_INSN_LDLOL
 , SH_INSN_LDLOQ, SH_INSN_LDXB, SH_INSN_LDXL, SH_INSN_LDXQ
 , SH_INSN_LDXUB, SH_INSN_LDXUW, SH_INSN_LDXW, SH_INSN_MABSL
 , SH_INSN_MABSW, SH_INSN_MADDL, SH_INSN_MADDW, SH_INSN_MADDSL
 , SH_INSN_MADDSUB, SH_INSN_MADDSW, SH_INSN_MCMPEQB, SH_INSN_MCMPEQL
 , SH_INSN_MCMPEQW, SH_INSN_MCMPGTL, SH_INSN_MCMPGTUB, SH_INSN_MCMPGTW
 , SH_INSN_MCMV, SH_INSN_MCNVSLW, SH_INSN_MCNVSWB, SH_INSN_MCNVSWUB
 , SH_INSN_MEXTR1, SH_INSN_MEXTR2, SH_INSN_MEXTR3, SH_INSN_MEXTR4
 , SH_INSN_MEXTR5, SH_INSN_MEXTR6, SH_INSN_MEXTR7, SH_INSN_MMACFXWL
 , SH_INSN_MMACNFX_WL, SH_INSN_MMULL, SH_INSN_MMULW, SH_INSN_MMULFXL
 , SH_INSN_MMULFXW, SH_INSN_MMULFXRPW, SH_INSN_MMULHIWL, SH_INSN_MMULLOWL
 , SH_INSN_MMULSUMWQ, SH_INSN_MOVI, SH_INSN_MPERMW, SH_INSN_MSADUBQ
 , SH_INSN_MSHALDSL, SH_INSN_MSHALDSW, SH_INSN_MSHARDL, SH_INSN_MSHARDW
 , SH_INSN_MSHARDSQ, SH_INSN_MSHFHIB, SH_INSN_MSHFHIL, SH_INSN_MSHFHIW
 , SH_INSN_MSHFLOB, SH_INSN_MSHFLOL, SH_INSN_MSHFLOW, SH_INSN_MSHLLDL
 , SH_INSN_MSHLLDW, SH_INSN_MSHLRDL, SH_INSN_MSHLRDW, SH_INSN_MSUBL
 , SH_INSN_MSUBW, SH_INSN_MSUBSL, SH_INSN_MSUBSUB, SH_INSN_MSUBSW
 , SH_INSN_MULSL, SH_INSN_MULUL, SH_INSN_NOP, SH_INSN_NSB
 , SH_INSN_OCBI, SH_INSN_OCBP, SH_INSN_OCBWB, SH_INSN_OR
 , SH_INSN_ORI, SH_INSN_PREFI, SH_INSN_PTA, SH_INSN_PTABS
 , SH_INSN_PTB, SH_INSN_PTREL, SH_INSN_PUTCFG, SH_INSN_PUTCON
 , SH_INSN_RTE, SH_INSN_SHARD, SH_INSN_SHARDL, SH_INSN_SHARI
 , SH_INSN_SHARIL, SH_INSN_SHLLD, SH_INSN_SHLLDL, SH_INSN_SHLLI
 , SH_INSN_SHLLIL, SH_INSN_SHLRD, SH_INSN_SHLRDL, SH_INSN_SHLRI
 , SH_INSN_SHLRIL, SH_INSN_SHORI, SH_INSN_SLEEP, SH_INSN_STB
 , SH_INSN_STL, SH_INSN_STQ, SH_INSN_STW, SH_INSN_STHIL
 , SH_INSN_STHIQ, SH_INSN_STLOL, SH_INSN_STLOQ, SH_INSN_STXB
 , SH_INSN_STXL, SH_INSN_STXQ, SH_INSN_STXW, SH_INSN_SUB
 , SH_INSN_SUBL, SH_INSN_SWAPQ, SH_INSN_SYNCI, SH_INSN_SYNCO
 , SH_INSN_TRAPA, SH_INSN_XOR, SH_INSN_XORI
} CGEN_INSN_TYPE;

/* Index of `invalid' insn place holder.  */
#define CGEN_INSN_INVALID SH_INSN_INVALID

/* Total number of insns in table.  */
#define MAX_INSNS ((int) SH_INSN_XORI + 1)

/* This struct records data prior to insertion or after extraction.  */
struct cgen_fields
{
  int length;
  long f_nil;
  long f_anyof;
  long f_op4;
  long f_op8;
  long f_op16;
  long f_sub4;
  long f_sub8;
  long f_sub10;
  long f_rn;
  long f_rm;
  long f_7_1;
  long f_11_1;
  long f_16_4;
  long f_disp8;
  long f_disp12;
  long f_imm8;
  long f_imm4;
  long f_imm4x2;
  long f_imm4x4;
  long f_imm8x2;
  long f_imm8x4;
  long f_imm12x4;
  long f_imm12x8;
  long f_dn;
  long f_dm;
  long f_vn;
  long f_vm;
  long f_xn;
  long f_xm;
  long f_imm20_hi;
  long f_imm20_lo;
  long f_imm20;
  long f_op;
  long f_ext;
  long f_rsvd;
  long f_left;
  long f_right;
  long f_dest;
  long f_left_right;
  long f_tra;
  long f_trb;
  long f_likely;
  long f_6_3;
  long f_23_2;
  long f_imm6;
  long f_imm10;
  long f_imm16;
  long f_uimm6;
  long f_uimm16;
  long f_disp6;
  long f_disp6x32;
  long f_disp10;
  long f_disp10x8;
  long f_disp10x4;
  long f_disp10x2;
  long f_disp16;
};

#define CGEN_INIT_PARSE(od) \
{\
}
#define CGEN_INIT_INSERT(od) \
{\
}
#define CGEN_INIT_EXTRACT(od) \
{\
}
#define CGEN_INIT_PRINT(od) \
{\
}


#endif /* SH_OPC_H */
