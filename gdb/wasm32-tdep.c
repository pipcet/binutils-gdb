/* Common target dependent code for GDB on the asm.js target

   Copyright (C) 1988-2015 Free Software Foundation, Inc.
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

#include "defs.h"

#include <ctype.h>		/* XXX for isupper ().  */

#include "frame.h"
#include "inferior.h"
#include "infrun.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "dis-asm.h"		/* For register styles.  */
#include "regcache.h"
#include "reggroups.h"
#include "value.h"
#include "arch-utils.h"
#include "osabi.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "objfiles.h"
#include "gdbtypes.h"
#include "prologue-value.h"
#include "remote.h"
#include "target-descriptions.h"
#include "user-regs.h"

#include "wasm32-tdep.h"

#include "elf-bfd.h"
#include "coff/internal.h"
#include "elf/wasm32.h"

#include "record.h"
#include "record-full.h"

/* When arguments must be pushed onto the stack, they go on in reverse
   order.  The code below implements a FILO (stack) to do this.  */

struct stack_item
{
  int len;
  struct stack_item *prev;
  gdb_byte *data;
};

static struct stack_item *
push_stack_item (struct stack_item *prev, const gdb_byte *contents, int len)
{
  struct stack_item *si;
  si = XNEW (struct stack_item);
  si->data = (gdb_byte *) xmalloc (len);
  si->len = len;
  si->prev = prev;
  memcpy (si->data, contents, len);
  return si;
}

static struct stack_item *
pop_stack_item (struct stack_item *si)
{
  struct stack_item *dead = si;
  si = si->prev;
  xfree (dead->data);
  xfree (dead);
  return si;
}

struct wasm32_registers {
  unsigned long fp;
  unsigned long pc;
  unsigned long sp;
  unsigned long rv;

  unsigned long a[4];

  unsigned long r[8];
  unsigned long i[8];
  double f[8];
};

#define REGISTER_NAMES {                              \
    "fp", /* frame pointer. must not be eliminated */ \
    "pc", /* not really the PC */		      \
    "sp", /* stack pointer */			      \
    "rv", /* return value; per-thread */	      \
    "a0", /* argument registers; per-thread */        \
    "a1", /* argument registers; per-thread */        \
    "a2", /* argument registers; per-thread */        \
    "a3", /* argument registers; per-thread */        \
    "r0", /* general registers */		      \
    "r1",					      \
    "r2",					      \
    "r3",					      \
    "r4", /* general registers */		      \
    "r5",					      \
    "r6",					      \
    "r7",					      \
    "i0", /* integer; no difference to r* now */      \
    "i1",					      \
    "i2",					      \
    "i3",					      \
    "i4", /* integer; no difference to r* now */      \
    "i5",					      \
    "i6",					      \
    "i7",					      \
    "f0", /* floating-point registers */	      \
    "f1",					      \
    "f2",					      \
    "f3",					      \
    "f4", /* floating-point registers */	      \
    "f5",					      \
    "f6",					      \
    "f7",					      \
    "ap", /* argument pointer; eliminated */	      \
    "tp", /* thread pointer; per-thread */	      \
}

static const char *const wasm32_register_names[] =
  REGISTER_NAMES;

/* Return the register name corresponding to register I.  */
static const char *
wasm32_register_name (struct gdbarch *gdbarch, int i)
{
  if (i >= ARRAY_SIZE (wasm32_register_names))
    /* These registers are only supported on targets which supply
       an XML description.  */
    return "";

  return wasm32_register_names[i];
}

static CORE_ADDR
wasm32_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  (void) gdbarch;

  return pc+0x10;
}

static const unsigned char *
wasm32_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr, int *lenptr)
{
  (void) gdbarch;
  (void) pcptr;
  *lenptr = 4;

  return NULL;
}

static int
wasm32_breakpoint_kind_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr)
{
  (void) gdbarch;
  (void) pcptr;

  return 0;
}

/* we're abusing this to skip the non-breakpointable first PC value
 * in a function. */
static CORE_ADDR
wasm32_skip_entrypoint (struct gdbarch *gdbarch ATTRIBUTE_UNUSED,
		       CORE_ADDR pc)
{
  return pc;
}

static int bp_max = 0;
static int bp_cur = 0;

static CORE_ADDR bp_addrs[] = {
  22179856, // XXX
  22179860, // XXX
  22179864, // XXX
  22179868, // XXX
};

static int
wasm32_memory_insert_breakpoint (struct gdbarch *gdbarch ATTRIBUTE_UNUSED,
				struct bp_target_info *bp_tgt)
{
  CORE_ADDR addr = bp_tgt->reqstd_address;
  int val;

  addr >>= 4;

  if ((addr & 0xff) == 0) {
    addr++;
  }
  bp_tgt->placed_address = addr<<4;

  if (bp_cur >= bp_max)
    error (_("Out of pseudo-software breakpoint slots."));

#if 0
  buf[0] = addr;
  buf[1] = addr>>8;
  buf[2] = addr>>16;
  buf[3] = addr>>24;

  val = target_write_memory (bp_addrs[bp_cur++], buf, 4);
  if (val != 0)
    {
      buf[0] = buf[1] = buf[2] = buf[3] = 255;
      target_write_memory (bp_addrs[--bp_cur], buf, 4);
    }
#endif
  val = 0;

  return val;
}

static int
wasm32_memory_remove_breakpoint (struct gdbarch *gdbarch ATTRIBUTE_UNUSED,
				struct bp_target_info *bp_tgt)
{
  /* XXX broken for bp_max > 1 */
  unsigned char buf[4];
  int val;

  if (bp_cur <= 0)
    error (_("Internal error clearing pseudo-software breakpoint."));

  buf[0] = buf[1] = buf[2] = buf[3] = 255;
  val = target_write_memory (bp_addrs[--bp_cur], buf, 4);

  return val;
}

extern "C" {
  int print_insn_wasm32 (bfd_vma pc, struct disassemble_info *info);
};

static int
gdb_print_insn_wasm32 (bfd_vma memaddr, disassemble_info *info)
{
  return print_insn_wasm32 (memaddr, info);
}

static struct type *
wasm32_register_type (struct gdbarch *gdbarch, int regnum)
{
  if (regnum == WASM32_SP_REGNUM || regnum == WASM32_FP_REGNUM)
    return builtin_type (gdbarch)->builtin_data_ptr;
  else if (regnum == WASM32_PC_REGNUM)
    return builtin_type (gdbarch)->builtin_func_ptr;
  else if (regnum >= WASM32_F0_REGNUM && regnum < WASM32_F0_REGNUM + 8)
    return builtin_type (gdbarch)->builtin_double;
  else
    return builtin_type (gdbarch)->builtin_uint32;
}

static struct frame_id
wasm32_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build (get_frame_register_unsigned (this_frame,
						      WASM32_SP_REGNUM),
			 get_frame_pc (this_frame));
}

static CORE_ADDR
wasm32_unwind_pc (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  CORE_ADDR pc;
  pc = frame_unwind_register_unsigned (this_frame, WASM32_PC_REGNUM);
  return pc;
}

static CORE_ADDR
wasm32_unwind_sp (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  CORE_ADDR pc;
  pc = frame_unwind_register_unsigned (this_frame, WASM32_SP_REGNUM);
  return pc;
}


static struct value *
wasm32_prev_register (struct frame_info *this_frame,
		     void **this_cache,
		     int prev_regnum)
{
  int i;
  unsigned off;

  unsigned regsize;
  unsigned regmask;
  unsigned prevfp;
  unsigned prevpc;
  unsigned size = (prev_regnum >= 24 && prev_regnum <= 31) ? 8 : 4;

  unsigned long long buf = 0;

  *this_cache = (void *)get_frame_register_unsigned (this_frame, WASM32_FP_REGNUM);

  read_memory((unsigned long)*this_cache, (gdb_byte *)&regmask, 4);
  read_memory((unsigned long)*this_cache + 12, (gdb_byte *)&regsize, 4);
  read_memory((unsigned long)*this_cache + regsize, (gdb_byte *)&prevpc, 4);
  read_memory((unsigned long)*this_cache + regsize + 4, (gdb_byte *)&prevfp, 4);
  read_memory(prevfp, (gdb_byte *)&regmask, 4);
  read_memory(prevfp + 12, (gdb_byte *)&regsize, 4);

  if (prev_regnum == WASM32_FP_REGNUM) {
    return frame_unwind_got_constant (this_frame, prev_regnum, prevfp);
  }
  if (prev_regnum == WASM32_PC_REGNUM) {
    return frame_unwind_got_constant (this_frame, prev_regnum, prevpc);
  }
  for (i = 0, off = 0; i < prev_regnum && off < regsize; i++)
    {
      unsigned long nsize = (i >= 24 && i <= 31) ? 8 : 4;
      if (regmask&(1<<i))
	{
	  off += (off&(nsize>>1)) + nsize;
	}
    }

  if (size == 8)
    off += off&4;

  if (regmask&(1 << prev_regnum))
    read_memory(prevfp + off, (gdb_byte *)&buf, size);

  return frame_unwind_got_constant (this_frame, prev_regnum, buf);
}

/* Our frame ID for a normal frame is the current function's starting PC
   and the caller's SP when we were called.  */

static void
wasm32_this_id (struct frame_info *this_frame,
		      void **this_cache,
		      struct frame_id *this_id)
{
  struct frame_id id;
  CORE_ADDR pc, func;

  pc = get_frame_pc (this_frame);
  func = get_frame_func (this_frame);
  if (!func)
    func = pc;

  id = frame_id_build (0, func);
  *this_id = id;
}

struct frame_unwind wasm32_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  wasm32_this_id,
  wasm32_prev_register,
  NULL,
  default_frame_sniffer,
};

static void
wasm32_extract_return_value (struct type *type, struct regcache *regs,
			  gdb_byte *valbuf)
{
}

static void
wasm32_store_return_value (struct type *type, struct regcache *regs,
			const gdb_byte *valbuf)
{
}

/* Handle function return values.  */

static enum return_value_convention
wasm32_return_value (struct gdbarch *gdbarch, struct value *function,
		  struct type *valtype, struct regcache *regcache,
		  gdb_byte *readbuf, const gdb_byte *writebuf)
{
  if (readbuf)
    wasm32_extract_return_value (valtype, regcache, readbuf);

  if (writebuf)
    wasm32_store_return_value (valtype, regcache, writebuf);

  if (readbuf)
    {
      ULONGEST sp;
      CORE_ADDR addr;

      regcache_cooked_read_unsigned (regcache, WASM32_SP_REGNUM, &sp);
      addr = read_memory_unsigned_integer (sp + 16, 4, gdbarch_byte_order (gdbarch));
      read_memory (addr, readbuf, TYPE_LENGTH (valtype));
    }

  if (writebuf)
    {
      ULONGEST sp;
      CORE_ADDR addr;

      regcache_cooked_read_unsigned (regcache, WASM32_SP_REGNUM, &sp);
      addr = read_memory_unsigned_integer (sp + 16, 4, gdbarch_byte_order (gdbarch));
      write_memory (addr, writebuf, TYPE_LENGTH (valtype));
    }

  return RETURN_VALUE_ABI_PRESERVES_ADDRESS;
}

/* We currently only support passing parameters in integer registers, which
   conforms with GCC's default model, and VFP argument passing following
   the VFP variant of AAPCS.  Several other variants exist and
   we should probably support some of them based on the selected ABI.  */

#define arm_debug 1
#define wasm32_type_align(type) 4

static CORE_ADDR
wasm32_push_dummy_code (struct gdbarch *gdbarch, CORE_ADDR sp, CORE_ADDR funaddr,
		       struct value **args, int nargs, struct type *value_type,
		       CORE_ADDR *real_pc, CORE_ADDR *bp_addr,
		       struct regcache *regcache)
{
  *bp_addr = 14381056; // XXX, obviously.
  *real_pc = funaddr;

  return sp;
}

static CORE_ADDR
wasm32_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
		       struct regcache *regcache, CORE_ADDR bp_addr, int nargs,
		       struct value **args, CORE_ADDR sp, function_call_return_method method,
		       CORE_ADDR struct_addr)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  gdb_byte buf[4];
  int argnum;
  int nstack;
  struct stack_item *si = NULL;

  /* Walk through the list of args and determine how large a temporary
     stack is required.  Need to take care here as structs may be
     passed on the stack, and we have to push them.  */
  nstack = 0;

  for (argnum = 0; argnum < nargs; argnum++)
    {
      int len;
      struct type *arg_type;
      const bfd_byte *val;
      int align;

      arg_type = check_typedef (value_type (args[argnum]));
      len = TYPE_LENGTH (arg_type);
      val = value_contents (args[argnum]);

      align = wasm32_type_align (arg_type);
      /* Round alignment up to a whole number of words.  */
      align = (align + INT_REGISTER_SIZE - 1) & ~(INT_REGISTER_SIZE - 1);

      /* Push stack padding for dowubleword alignment.  */
      if (nstack & (align - 1))
	{
	  si = push_stack_item (si, val, INT_REGISTER_SIZE);
	  nstack += INT_REGISTER_SIZE;
	}

      while (len > 0)
	{
	  int partial_len = len < INT_REGISTER_SIZE ? len : INT_REGISTER_SIZE;

	  /* Push the arguments onto the stack.  */
	  if (arm_debug)
	    fprintf_unfiltered (gdb_stdlog, "arg %d @ sp + %d\n",
				argnum, nstack);
	  si = push_stack_item (si, val, INT_REGISTER_SIZE);
	  nstack += INT_REGISTER_SIZE;

	  len -= partial_len;
	  val += partial_len;
	}
    }

  /* If we have an odd number of words to push, then decrement the stack
     by one word now, so first stack argument will be dword aligned.  */
  if (nstack & 4)
    sp -= 4;

  while (si)
    {
      sp -= si->len;
      write_memory (sp, si->data, si->len);
      si = pop_stack_item (si);
    }

  regcache_cooked_write_unsigned (regcache, WASM32_R0_REGNUM+1, nargs);

  store_unsigned_integer (buf, 4, byte_order, bp_addr);
  write_memory (sp -= 4, buf, 4);

  /* Finally, update the SP register.  */
  regcache_cooked_write_unsigned (regcache, WASM32_SP_REGNUM, sp);

  return sp;
}

static struct gdbarch *
wasm32_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch_tdep *tdep;
  struct gdbarch *gdbarch;
  struct tdesc_arch_data *tdesc_data = NULL;
  int i;
  const struct target_desc *tdesc = info.target_desc;

  /* Check any target description for validity.  */
  if (tdesc_has_registers (tdesc))
    {
      const struct tdesc_feature *feature = NULL;
      int valid_p;

      tdesc_data = tdesc_data_alloc ();

      valid_p = 1;
      for (i = 0; i < WASM32_SP_REGNUM; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
					    wasm32_register_names[i]);

      if (!valid_p)
	{
	  tdesc_data_cleanup (tdesc_data);
	  return NULL;
	}

    }

  tdep = XNEW (struct gdbarch_tdep);
  gdbarch = gdbarch_alloc (&info, tdep);

  /* On WASM32 targets char defaults to unsigned.  */
  set_gdbarch_char_signed (gdbarch, 0); // XXX

  set_gdbarch_call_dummy_location (gdbarch, ON_STACK);
  set_gdbarch_push_dummy_code (gdbarch, wasm32_push_dummy_code);
  set_gdbarch_push_dummy_call (gdbarch, wasm32_push_dummy_call);
  /* Frame handling.  */
  set_gdbarch_dummy_id (gdbarch, wasm32_dummy_id);
  set_gdbarch_unwind_pc (gdbarch, wasm32_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, wasm32_unwind_sp);

  /* The stack grows downward.  */
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);

  /* Information about registers, etc.  */
  set_gdbarch_sp_regnum (gdbarch, WASM32_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, WASM32_PC_REGNUM);
  set_gdbarch_num_regs (gdbarch, WASM32_NUM_REGS);
  set_gdbarch_register_type (gdbarch, wasm32_register_type);

  /* Disassembly.  */
  //set_gdbarch_print_insn (gdbarch, gdb_print_insn_wasm32);

  /* Virtual tables.  */
  set_gdbarch_vbit_in_delta (gdbarch, 1);

  /* Hook in the ABI-specific overrides, if they have been registered.  */
  gdbarch_init_osabi (info, gdbarch);

  //dwarf2_frame_set_init_reg (gdbarch, wasm32_dwarf2_frame_init_reg);

  /* Now we have tuned the configuration, set a few final things,
     based on what the OS ABI has told us.  */

  set_gdbarch_register_name (gdbarch, wasm32_register_name);

  /* Returning results.  */
  set_gdbarch_return_value (gdbarch, wasm32_return_value);

  frame_unwind_append_unwinder (gdbarch, &wasm32_unwind);

  //dwarf2_append_unwinders (gdbarch);

  /* Watchpoints are not steppable.  */
  set_gdbarch_have_nonsteppable_watchpoint (gdbarch, 1);

  /* Floating point sizes and format.  */
  set_gdbarch_float_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_double_format (gdbarch, floatformats_ieee_double);
  set_gdbarch_long_double_format (gdbarch, floatformats_ieee_double);

  /* Advance PC across function entry code.  */
  set_gdbarch_skip_prologue (gdbarch, wasm32_skip_prologue);

  /* Disassembly.  */
  set_gdbarch_print_insn (gdbarch, gdb_print_insn_wasm32);

  /* Breakpoint manipulation.  */
  set_gdbarch_breakpoint_from_pc (gdbarch, wasm32_breakpoint_from_pc);
  set_gdbarch_breakpoint_kind_from_pc (gdbarch, wasm32_breakpoint_kind_from_pc);
  set_gdbarch_memory_insert_breakpoint (gdbarch, wasm32_memory_insert_breakpoint);
  set_gdbarch_memory_remove_breakpoint (gdbarch, wasm32_memory_remove_breakpoint);
  set_gdbarch_skip_entrypoint (gdbarch, wasm32_skip_entrypoint);

  return gdbarch;
}

extern initialize_file_ftype _initialize_wasm32_tdep; /* -Wmissing-prototypes */

void
_initialize_wasm32_tdep (void)
{
  gdbarch_register (bfd_arch_wasm32, wasm32_gdbarch_init, NULL);
}
