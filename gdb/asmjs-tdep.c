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
#include "doublest.h"
#include "value.h"
#include "arch-utils.h"
#include "osabi.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "objfiles.h"
#include "dwarf2-frame.h"
#include "gdbtypes.h"
#include "prologue-value.h"
#include "remote.h"
#include "target-descriptions.h"
#include "user-regs.h"
#include "observer.h"

#include "asmjs-tdep.h"

#include "elf-bfd.h"
#include "coff/internal.h"
#include "elf/asmjs.h"

#include "vec.h"

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

struct asmjs_registers {
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

static const char *const asmjs_register_names[] =
  REGISTER_NAMES;

/* Return the register name corresponding to register I.  */
static const char *
asmjs_register_name (struct gdbarch *gdbarch, int i)
{
  if (i >= ARRAY_SIZE (asmjs_register_names))
    /* These registers are only supported on targets which supply
       an XML description.  */
    return "";

  return asmjs_register_names[i];
}

static CORE_ADDR
asmjs_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  (void) gdbarch;

  return pc+0x10;
}

static const unsigned char *
asmjs_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr, int *lenptr)
{
  (void) gdbarch;
  (void) pcptr;
  *lenptr = 4;

  return NULL;
}

static int
asmjs_breakpoint_kind_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr)
{
  (void) gdbarch;
  (void) pcptr;

  return 0;
}

#if 0
static void
asmjs_remote_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr, int *lenptr)
{
  (void) gdbarch;
  (void) pcptr;
  if ((*pcptr&0xfff) == 0x000) {
  }
  *lenptr = 4;
}
#endif

/* we're abusing this to skip the non-breakpointable first PC value
 * in a function. */
static CORE_ADDR
asmjs_skip_entrypoint (struct gdbarch *gdbarch ATTRIBUTE_UNUSED,
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
asmjs_memory_insert_breakpoint (struct gdbarch *gdbarch ATTRIBUTE_UNUSED,
				struct bp_target_info *bp_tgt)
{
  CORE_ADDR addr = bp_tgt->reqstd_address;
  unsigned char buf[4];
  int val;

#if 0
  addr >>= 4;

  if ((addr & 0xff) == 0) {
    addr++;
  }
  bp_tgt->placed_address = addr<<4;
  bp_tgt->placed_size = 4;

  if (bp_cur >= bp_max)
    error (_("Out of pseudo-software breakpoint slots."));

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
asmjs_memory_remove_breakpoint (struct gdbarch *gdbarch ATTRIBUTE_UNUSED,
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

extern int
print_insn_little_asmjs (bfd_vma pc, struct disassemble_info *info);

static int
gdb_print_insn_asmjs (bfd_vma memaddr, disassemble_info *info)
{
  return print_insn_little_asmjs (memaddr, info);
}

static struct type *
asmjs_register_type (struct gdbarch *gdbarch, int regnum)
{
  if (regnum == ASMJS_SP_REGNUM || regnum == ASMJS_FP_REGNUM)
    return builtin_type (gdbarch)->builtin_data_ptr;
  else if (regnum == ASMJS_PC_REGNUM)
    return builtin_type (gdbarch)->builtin_func_ptr;
  else if (regnum >= ASMJS_F0_REGNUM && regnum < ASMJS_F0_REGNUM + 8)
    return builtin_type (gdbarch)->builtin_double;
  else
    return builtin_type (gdbarch)->builtin_uint32;
}

static struct frame_id
asmjs_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build (get_frame_register_unsigned (this_frame,
						      ASMJS_SP_REGNUM),
			 get_frame_pc (this_frame));
}

static CORE_ADDR
asmjs_unwind_pc (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  CORE_ADDR pc;
  pc = frame_unwind_register_unsigned (this_frame, ASMJS_PC_REGNUM);
  return pc;
}

static CORE_ADDR
asmjs_unwind_sp (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  CORE_ADDR pc;
  pc = frame_unwind_register_unsigned (this_frame, ASMJS_SP_REGNUM);
  return pc;
}


static struct value *
asmjs_prev_register (struct frame_info *this_frame,
		     void **this_cache,
		     int prev_regnum)
{
  struct trad_frame_saved_reg *regs = trad_frame_alloc_saved_regs (this_frame);
  int i;
  unsigned off;

  unsigned regsize;
  unsigned regmask;
  unsigned prevfp;
  unsigned prevpc;
  unsigned size = (prev_regnum >= 24 && prev_regnum <= 31) ? 8 : 4;

  unsigned long long buf = 0;

  *this_cache = (void *)get_frame_register_unsigned (this_frame, ASMJS_FP_REGNUM);

  read_memory((unsigned long)*this_cache, (gdb_byte *)&regmask, 4);
  read_memory((unsigned long)*this_cache + 12, (gdb_byte *)&regsize, 4);
  read_memory((unsigned long)*this_cache + regsize, (gdb_byte *)&prevpc, 4);
  read_memory((unsigned long)*this_cache + regsize + 4, (gdb_byte *)&prevfp, 4);
  read_memory(prevfp, (gdb_byte *)&regmask, 4);
  read_memory(prevfp + 12, (gdb_byte *)&regsize, 4);

  if (prev_regnum == ASMJS_FP_REGNUM) {
    return frame_unwind_got_constant (this_frame, prev_regnum, prevfp);
  }
  if (prev_regnum == ASMJS_PC_REGNUM) {
    return frame_unwind_got_constant (this_frame, prev_regnum, prevpc);
  }
  for (i = 0, off = 0; i < prev_regnum && off < regsize; i++)
    {
      unsigned long size = (i >= 24 && i <= 31) ? 8 : 4;
      if (regmask&(1<<i))
	{
	  off += (off&(size>>1)) + size;
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
asmjs_this_id (struct frame_info *this_frame,
		      void **this_cache,
		      struct frame_id *this_id)
{
  struct arm_prologue_cache *cache;
  struct frame_id id;
  CORE_ADDR pc, func;

  pc = get_frame_pc (this_frame);
  func = get_frame_func (this_frame);
  if (!func)
    func = pc;

  id = frame_id_build (0, func);
  *this_id = id;
}

struct frame_unwind asmjs_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  asmjs_this_id,
  asmjs_prev_register,
  NULL,
  default_frame_sniffer,
};

static void
asmjs_extract_return_value (struct type *type, struct regcache *regs,
			  gdb_byte *valbuf)
{
}

static void
asmjs_store_return_value (struct type *type, struct regcache *regs,
			const gdb_byte *valbuf)
{
}

/* Handle function return values.  */

static enum return_value_convention
asmjs_return_value (struct gdbarch *gdbarch, struct value *function,
		  struct type *valtype, struct regcache *regcache,
		  gdb_byte *readbuf, const gdb_byte *writebuf)
{
  if (readbuf)
    asmjs_extract_return_value (valtype, regcache, readbuf);

  if (writebuf)
    asmjs_store_return_value (valtype, regcache, writebuf);

  if (readbuf)
    {
      ULONGEST sp;
      CORE_ADDR addr;

      regcache_cooked_read_unsigned (regcache, ASMJS_SP_REGNUM, &sp);
      addr = read_memory_unsigned_integer (sp + 16, 4, gdbarch_byte_order (gdbarch));
      read_memory (addr, readbuf, TYPE_LENGTH (valtype));
    }

  if (writebuf)
    {
      ULONGEST sp;
      CORE_ADDR addr;

      regcache_cooked_read_unsigned (regcache, ASMJS_SP_REGNUM, &sp);
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
#define asmjs_type_align(type) 4

static CORE_ADDR
asmjs_push_dummy_code (struct gdbarch *gdbarch, CORE_ADDR sp, CORE_ADDR funaddr,
		       struct value **args, int nargs, struct type *value_type,
		       CORE_ADDR *real_pc, CORE_ADDR *bp_addr,
		       struct regcache *regcache)
{
  *bp_addr = 14381056; // XXX, obviously.
  *real_pc = funaddr;

  return sp;
}

static CORE_ADDR
asmjs_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
		       struct regcache *regcache, CORE_ADDR bp_addr, int nargs,
		       struct value **args, CORE_ADDR sp, int struct_return,
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
#if 0
      struct type *target_type;
      enum type_code typecode;
#endif
      const bfd_byte *val;
      int align;

      arg_type = check_typedef (value_type (args[argnum]));
      len = TYPE_LENGTH (arg_type);
#if 0
      target_type = TYPE_TARGET_TYPE (arg_type);
      typecode = TYPE_CODE (arg_type);
#endif
      val = value_contents (args[argnum]);

      align = asmjs_type_align (arg_type);
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

  regcache_cooked_write_unsigned (regcache, ASMJS_R0_REGNUM+1, nargs);

  store_unsigned_integer (buf, 4, byte_order, bp_addr);
  write_memory (sp -= 4, buf, 4);

  /* Finally, update the SP register.  */
  regcache_cooked_write_unsigned (regcache, ASMJS_SP_REGNUM, sp);

  return sp;
}

static struct gdbarch *
asmjs_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch_tdep *tdep;
  struct gdbarch *gdbarch;
  struct gdbarch_list *best_arch;
  struct tdesc_arch_data *tdesc_data = NULL;
  int i, is_m = 0;
  int have_wmmx_registers = 0;
  int have_neon = 0;
  int have_fpa_registers = 1;
  const struct target_desc *tdesc = info.target_desc;

  /* Check any target description for validity.  */
  if (tdesc_has_registers (tdesc))
    {
      /* For most registers we require GDB's default names; but also allow
	 the numeric names for sp / lr / pc, as a convenience.  */
      static const char *const asmjs_sp_names[] = { "r13", "sp", NULL };
      static const char *const asmjs_lr_names[] = { "r14", "lr", NULL };
      static const char *const asmjs_pc_names[] = { "r15", "pc", NULL };

      const struct tdesc_feature *feature = NULL;
      int valid_p;

      tdesc_data = tdesc_data_alloc ();

      valid_p = 1;
      for (i = 0; i < ASMJS_SP_REGNUM; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
					    asmjs_register_names[i]);
      valid_p &= tdesc_numbered_register_choices (feature, tdesc_data,
						  ASMJS_SP_REGNUM,
						  asmjs_sp_names);
      valid_p &= tdesc_numbered_register_choices (feature, tdesc_data,
						  ASMJS_FP_REGNUM,
						  asmjs_lr_names);
      valid_p &= tdesc_numbered_register_choices (feature, tdesc_data,
						  ASMJS_PC_REGNUM,
						  asmjs_pc_names);

      if (!valid_p)
	{
	  tdesc_data_cleanup (tdesc_data);
	  return NULL;
	}

    }

  tdep = XNEW (struct gdbarch_tdep);
  gdbarch = gdbarch_alloc (&info, tdep);

  /* On ASMJS targets char defaults to unsigned.  */
  set_gdbarch_char_signed (gdbarch, 0); // XXX

  set_gdbarch_call_dummy_location (gdbarch, ON_STACK);
  set_gdbarch_push_dummy_code (gdbarch, asmjs_push_dummy_code);
  set_gdbarch_push_dummy_call (gdbarch, asmjs_push_dummy_call);
  /* Frame handling.  */
  set_gdbarch_dummy_id (gdbarch, asmjs_dummy_id);
  set_gdbarch_unwind_pc (gdbarch, asmjs_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, asmjs_unwind_sp);

  /* The stack grows downward.  */
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);

  /* Information about registers, etc.  */
  set_gdbarch_sp_regnum (gdbarch, ASMJS_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, ASMJS_PC_REGNUM);
  set_gdbarch_num_regs (gdbarch, ASMJS_NUM_REGS);
  set_gdbarch_register_type (gdbarch, asmjs_register_type);

  /* Disassembly.  */
  //set_gdbarch_print_insn (gdbarch, gdb_print_insn_asmjs);

  /* Virtual tables.  */
  set_gdbarch_vbit_in_delta (gdbarch, 1);

  /* Hook in the ABI-specific overrides, if they have been registered.  */
  gdbarch_init_osabi (info, gdbarch);

  //dwarf2_frame_set_init_reg (gdbarch, asmjs_dwarf2_frame_init_reg);

  /* Now we have tuned the configuration, set a few final things,
     based on what the OS ABI has told us.  */

  set_gdbarch_register_name (gdbarch, asmjs_register_name);

  /* Returning results.  */
  set_gdbarch_return_value (gdbarch, asmjs_return_value);

  frame_unwind_append_unwinder (gdbarch, &asmjs_unwind);

  dwarf2_append_unwinders (gdbarch);

  /* Watchpoints are not steppable.  */
  set_gdbarch_have_nonsteppable_watchpoint (gdbarch, 1);

  /* Floating point sizes and format.  */
  set_gdbarch_float_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_double_format (gdbarch, floatformats_ieee_double);
  set_gdbarch_long_double_format (gdbarch, floatformats_ieee_double);

  /* Advance PC across function entry code.  */
  set_gdbarch_skip_prologue (gdbarch, asmjs_skip_prologue);

  /* Disassembly.  */
  set_gdbarch_print_insn (gdbarch, gdb_print_insn_asmjs);

  /* Breakpoint manipulation.  */
  set_gdbarch_breakpoint_from_pc (gdbarch, asmjs_breakpoint_from_pc);
  set_gdbarch_breakpoint_kind_from_pc (gdbarch, asmjs_breakpoint_kind_from_pc);
  //set_gdbarch_remote_breakpoint_from_pc (gdbarch, asmjs_remote_breakpoint_from_pc);
  set_gdbarch_memory_insert_breakpoint (gdbarch, asmjs_memory_insert_breakpoint);
  set_gdbarch_memory_remove_breakpoint (gdbarch, asmjs_memory_remove_breakpoint);
  set_gdbarch_skip_entrypoint (gdbarch, asmjs_skip_entrypoint);

  return gdbarch;
}

extern initialize_file_ftype _initialize_asmjs_tdep; /* -Wmissing-prototypes */

void
_initialize_asmjs_tdep (void)
{
  struct ui_file *stb;
  long length;
  struct cmd_list_element *new_set, *new_show;
  const char *setname;
  const char *setdesc;
  const char *const *regnames;
  int numregs, i, j;
  static char *helptext;
  char regdesc[1024], *rdptr = regdesc;
  size_t rest = sizeof (regdesc);

  gdbarch_register (bfd_arch_asmjs, asmjs_gdbarch_init, NULL);
}
