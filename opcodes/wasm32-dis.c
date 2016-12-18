/* "Instruction" printing code for the asm.js target
   Copyright (C) 1994-2015 Free Software Foundation, Inc.
   Copyright (C) 2016 Pip Cet <pipcet@gmail.com>

   This file is NOT part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"

#include "dis-asm.h"
#include "opintl.h"
#include "safe-ctype.h"
#include "floatformat.h"

/* FIXME: This shouldn't be done here.  */
#include "coff/internal.h"
#include "libcoff.h"
#include "elf-bfd.h"
#include "elf/internal.h"
#include "elf/wasm32.h"

/* FIXME: Belongs in global header.  */
#ifndef strneq
#define strneq(a,b,n)	(strncmp ((a), (b), (n)) == 0)
#endif

#ifndef NUM_ELEM
#define NUM_ELEM(a)     (sizeof (a) / sizeof (a)[0])
#endif



enum wasm_clas { wasm_typed, wasm_special, wasm_special1, wasm_break, wasm_fakebreak, wasm_break_if, wasm_break_table,
                 wasm_return, wasm_call, wasm_call_import, wasm_call_indirect, wasm_get_local, wasm_set_local, wasm_tee_local, wasm_drop,
                 wasm_constant_i32, wasm_constant_i64, wasm_constant_f32, wasm_constant_f64, wasm_unary, wasm_binary,
wasm_conv, wasm_load, wasm_store, wasm_select, wasm_relational, wasm_eqz, wasm_signature };

enum wasm_signedness { wasm_signed, wasm_unsigned, wasm_agnostic, wasm_floating };

enum wasm_type { wasm_void, wasm_any, wasm_i32, wasm_i64, wasm_f32, wasm_f64 };

#define WASM_OPCODE(name, intype, outtype, clas, signedness, opcode) \
  { name, wasm_ ## intype, wasm_ ## outtype, wasm_ ## clas, wasm_ ## signedness, opcode },

struct wasm32_opcode_s {
  const char *name;
  enum wasm_type intype;
  enum wasm_type outtype;
  enum wasm_clas clas;
  enum wasm_signedness signedness;
  unsigned char opcode;
} wasm32_opcodes[] = {
#include "opcode/wasm.h"
  { NULL, 0, 0, 0, 0, 0 }
};

bfd_boolean
wasm32_symbol_is_valid (asymbol * sym,
                       struct disassemble_info * info ATTRIBUTE_UNUSED);
bfd_boolean
wasm32_symbol_is_valid (asymbol * sym,
		     struct disassemble_info * info ATTRIBUTE_UNUSED)
{
  if (sym == NULL)
    return FALSE;

  if (strcmp(sym->section->name, "*ABS*") == 0)
    return FALSE;

  return TRUE;
}

/* Parse an individual disassembler option.  */

void
parse_wasm32_disassembler_option (char *option);
void
parse_wasm32_disassembler_option (char *option)
{
  if (option == NULL)
    return;

  /* XXX - should break 'option' at following delimiter.  */
  fprintf (stderr, _("Unrecognised disassembler option: %s\n"), option);

  return;
}

/* Parse the string of disassembler options, spliting it at whitespaces
   or commas.  (Whitespace separators supported for backwards compatibility).  */

extern
int read_uleb128(long *value, bfd_vma pc, struct disassemble_info *info);

int read_uleb128(long *value, bfd_vma pc, struct disassemble_info *info)
{
  bfd_byte buffer[16];
  int len = 1;

  if (info->read_memory_func (pc, buffer, 1, info))
    return -1;

  if (buffer[0] & 0x80)
    {
      len = read_uleb128(value, pc + 1, info) + 1;
    }
  *value <<= 7;
  *value |= buffer[0]&0x7f;

  return len;
}

int read_u32(long *value, bfd_vma pc, struct disassemble_info *info);
int read_u32(long *value, bfd_vma pc, struct disassemble_info *info)
{
  int ret;

  if (info->read_memory_func (pc, (bfd_byte*)&ret, 4, info))
    return -1;

  *value = ret;

  return 4;
}

int read_f32(double *value, bfd_vma pc, struct disassemble_info *info);
int read_f32(double *value, bfd_vma pc, struct disassemble_info *info)
{
  float ret;

  if (info->read_memory_func (pc, (bfd_byte*)&ret, 4, info))
    return -1;

  *value = ret;

  return 4;
}

int read_f64(double *value, bfd_vma pc, struct disassemble_info *info);
int read_f64(double *value, bfd_vma pc, struct disassemble_info *info)
{
  double ret;

  if (info->read_memory_func (pc, (bfd_byte*)&ret, 8, info))
    return -1;

  *value = ret;

  return 8;
}

const char *print_type(enum wasm_type);
const char *print_type(enum wasm_type type)
{
  switch (type) {
  case wasm_i32:
    return "i32";
  case wasm_f32:
    return "f32";
  case wasm_i64:
    return "i64";
  case wasm_f64:
    return "f64";
  default:
    return NULL;
  }
}

int
print_insn_little_wasm32 (bfd_vma pc, struct disassemble_info *info);
int
print_insn_little_wasm32 (bfd_vma pc, struct disassemble_info *info)
{
  unsigned char opcode;
  struct wasm32_opcode_s *op;
  bfd_byte buffer[16];
  void *stream = info->stream;
  fprintf_ftype prin = info->fprintf_func;
  long constant = 0;
  double fconstant = 0.0;
  long flags = 0;
  long offset = 0;
  long depth = 0;
  long index = 0;
  long target_count = 0;
  long block_type = 0;
  int len = 1;
  int i;
  const char *locals[] = {
    "$dpc", "$sp1", "$r0", "$r1", "$rpc", "$pc0",
    "$rp", "$fp", "$sp",
    "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
    "$i0", "$i1", "$i2", "$i3", "$i4", "$i5", "$i6", "$i7",
    "$f0", "$f1", "$f2", "$f3", "$f4", "$f5", "$f6", "$f7",
  };
  int nlocals = sizeof(locals) / sizeof(locals[0]);
  const char *globals[] = {
    "$got", "$plt", "$gpo"
  };
  int nglobals = sizeof(globals) / sizeof(globals[0]);
  (void) nglobals;

  if (info->read_memory_func (pc, buffer, 1, info))
    return -1;

  opcode = buffer[0];

  for (op = wasm32_opcodes; op->name; op++)
    if (op->opcode == opcode)
      break;

  if (!op->name)
    {
      prin (stream, "\t.byte %02x\n", buffer[0]);
      return 1;
    }
  else
    {
      len = 1;

      prin (stream, "\t");
      prin (stream, "%s", op->name);

      switch (op->clas)
        {
        case wasm_typed:
          len += read_uleb128(&block_type, pc + len, info);
          switch (block_type)
            {
            case 0x40:
              prin (stream, "[]");
              break;
            case 0x7f:
              prin (stream, "[i]");
              break;
            case 0x7e:
              prin (stream, "[l]");
              break;
            case 0x7d:
              prin (stream, "[f]");
              break;
            case 0x7c:
              prin (stream, "[d]");
              break;
            }
          break;
        case wasm_special:
          break;
        case wasm_special1:
          break;
        case wasm_binary:
        case wasm_relational:
        case wasm_store:
          break;
        case wasm_select:
          break;
        case wasm_eqz:
        case wasm_unary:
        case wasm_conv:
        case wasm_load:
        case wasm_set_local:
        case wasm_tee_local:
        case wasm_drop:
          break;
        case wasm_break_table:
        case wasm_break:
        case wasm_fakebreak:
        case wasm_return:
          break;
        case wasm_call:
        case wasm_call_import:
        case wasm_call_indirect:
          break;
        case wasm_break_if:
          break;
        case wasm_constant_i32:
        case wasm_constant_i64:
        case wasm_constant_f32:
        case wasm_constant_f64:
        case wasm_get_local:
        case wasm_signature:
          break;
        }

      switch (op->clas)
        {
        case wasm_special:
        case wasm_special1:
        case wasm_eqz:
        case wasm_binary:
        case wasm_unary:
        case wasm_conv:
        case wasm_relational:
        case wasm_drop:
          break;
        case wasm_typed:
        case wasm_select:
          break;
        case wasm_break_table:
          len += read_uleb128(&target_count, pc + len, info);
          //prin (stream, " %ld %ld", argument_count, target_count);
          for (i = 0; i < target_count + 1; i++)
            {
              long target = 0;
              len += read_uleb128(&target, pc + len, info);
              prin (stream, " %ld", target);
            }
          break;
        case wasm_fakebreak:
          {
            long n = 0;
            len += read_uleb128(&n, pc + len, info);
            prin (stream, "[%ld]", n);
            len += read_uleb128(&depth, pc + len, info);
            //prin (stream, " %ld %ld", argument_count, depth);
            prin (stream, " %ld", depth);
          }
          break;
        case wasm_break:
        case wasm_break_if:
          len += read_uleb128(&depth, pc + len, info);
          //prin (stream, " %ld %ld", argument_count, depth);
          prin (stream, " %ld", depth);
          break;
        case wasm_return:
          //prin (stream, " %ld", argument_count);
          break;
        case wasm_constant_i32:
        case wasm_constant_i64:
          len += read_uleb128(&constant, pc + len, info);
          prin (stream, " %lx", constant);
          break;
        case wasm_constant_f32:
          len += read_f32(&fconstant, pc + len, info);
          prin (stream, " %f", fconstant);
          break;
        case wasm_constant_f64:
          len += read_f64(&fconstant, pc + len, info);
          prin (stream, " %f", fconstant);
          break;
        case wasm_call:
          len += read_uleb128(&index, pc + len, info);
          prin (stream, " ");
          (*info->print_address_func) ((bfd_vma) index, info);
          break;
        case wasm_call_indirect:
          len += read_uleb128(&constant, pc + len, info);
          prin (stream, " %ld", constant);
          len += read_uleb128(&constant, pc + len, info);
          prin (stream, " %ld", constant);
          break;
        case wasm_get_local:
        case wasm_set_local:
        case wasm_tee_local:
          len += read_uleb128(&constant, pc + len, info);
          prin (stream, " %ld", constant);
          if (strcmp (op->name + 4, "local") == 0)
            {
              if (constant >= 0 && constant < nlocals)
                prin (stream, " <%s>", locals[constant]);
            }
          else
            {
              if (constant >= 0 && constant < nglobals)
                prin (stream, " <%s>", globals[constant]);
            }
          break;
        case wasm_load:
        case wasm_store:
          len += read_uleb128(&flags, pc + len, info);
          len += read_uleb128(&offset, pc + len, info);
          prin (stream, " a=%ld %ld", flags, offset);
        case wasm_signature:
        case wasm_call_import:
          break;
        }
    }
  return len;
}

void print_wasm32_disassembler_options(FILE *);
void
print_wasm32_disassembler_options (FILE *stream)
{
  fprintf (stream, _("\
The following WASM32 specific disassembler options are supported for use with\n\
the -M switch:\nnone\n"));
}
