/* Common target dependent code for GDB on the asm.js target
   Copyright (C) 2002-2015 Free Software Foundation, Inc.
   Copyright (C) 2016 Pip Cet <pipcet@gmail.com>

   This file is NOT part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef WASM_TDEP_H
#define WASM_TDEP_H

/* Forward declarations.  */
struct gdbarch;
struct regset;
struct address_space;

/* Register numbers of various important registers.  */

enum gdb_regnum {
  WASM_FP_REGNUM = 0,
  WASM_PC_REGNUM = 1,
  WASM_SP_REGNUM = 2,
  WASM_RV_REGNUM = 3,

  WASM_A0_REGNUM,
  WASM_A1_REGNUM,
  WASM_A2_REGNUM,
  WASM_A3_REGNUM,

  WASM_R0_REGNUM,
  WASM_R1_REGNUM,
  WASM_R2_REGNUM,
  WASM_R3_REGNUM,
  WASM_R4_REGNUM,
  WASM_R5_REGNUM,
  WASM_R6_REGNUM,
  WASM_R7_REGNUM,

  WASM_I0_REGNUM,
  WASM_I1_REGNUM,
  WASM_I2_REGNUM,
  WASM_I3_REGNUM,
  WASM_I4_REGNUM,
  WASM_I5_REGNUM,
  WASM_I6_REGNUM,
  WASM_I7_REGNUM,

  WASM_F0_REGNUM,
  WASM_F1_REGNUM,
  WASM_F2_REGNUM,
  WASM_F3_REGNUM,
  WASM_F4_REGNUM,
  WASM_F5_REGNUM,
  WASM_F6_REGNUM,
  WASM_F7_REGNUM,

  WASM_NUM_REGS,
};

/* Size of integer registers.  */
#define INT_REGISTER_SIZE		4

/* Say how long FP registers are.  Used for documentation purposes and
   code readability in this header.  IEEE extended doubles are 80
   bits.  DWORD aligned they use 96 bits.  */
#define FP_REGISTER_SIZE	8

/* Number of machine registers.  The only define actually required
   is gdbarch_num_regs.  The other definitions are used for documentation
   purposes and code readability.  */
/* For 26 bit WASM code, a fake copy of the PC is placed in register 25 (PS)
   (and called PS for processor status) so the status bits can be cleared
   from the PC (register 15).  For 32 bit WASM code, a copy of CPSR is placed
   in PS.  */
#define NUM_FREGS	8	/* Number of floating point registers.  */
#define NUM_SREGS	2	/* Number of status registers.  */
#define NUM_GREGS	16	/* Number of general purpose registers.  */


/* Target-dependent structure in gdbarch.  */
struct gdbarch_tdep
{
};

/* Structures used for displaced stepping.  */

/* The maximum number of temporaries available for displaced instructions.  */
#define DISPLACED_TEMPS			16
/* The maximum number of modified instructions generated for one single-stepped
   instruction, including the breakpoint (usually at the end of the instruction
   sequence) and any scratch words, etc.  */
#define DISPLACED_MODIFIED_INSNS	8

struct displaced_step_closure
{
};

extern int wasm_process_record (struct gdbarch *gdbarch,
			       struct regcache *regcache, CORE_ADDR addr);
/* Functions exported from wasmbsd-tdep.h.  */

/* Target descriptions.  */
extern struct target_desc *tdesc_wasm;

#endif /* wasm-tdep.h */
