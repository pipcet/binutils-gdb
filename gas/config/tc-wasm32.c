/* tc-wasm32.c -- Assembler code for the wasm32 target.

   Copyright (C) 1999-2015 Free Software Foundation, Inc.
   Copyright (C) 2016-2017 Pip Cet <pipcet@gmail.com>

   This file is NOT part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "as.h"
#include "safe-ctype.h"
#include "subsegs.h"
#include "dwarf2dbg.h"
#include "dw2gencfi.h"
#include "elf/wasm32.h"
#include <float.h>

enum wasm_clas
  {
    wasm_typed, /* a typed opcode: block, loop, and if */
    wasm_special, /* a special opcode: unreachable, nop, else, end */
    wasm_break, /* "br" */
    wasm_break_if, /* "br_if" opcode */
    wasm_break_table, /* "br_table" opcode */
    wasm_return, /* "return" opcode */
    wasm_call, /* "call" opcode */
    wasm_call_indirect, /* "call_indirect" opcode */
    wasm_get_local, /* "get_local" and "get_global" */
    wasm_set_local, /* "set_local" and "set_global" */
    wasm_tee_local, /* "tee_local" */
    wasm_drop, /* "drop" */
    wasm_constant_i32, /* "i32.const" */
    wasm_constant_i64, /* "i64.const" */
    wasm_constant_f32, /* "f32.const" */
    wasm_constant_f64, /* "f64.const" */
    wasm_unary, /* unary ops */
    wasm_binary, /* binary ops */
    wasm_conv, /* conversion ops */
    wasm_load, /* load ops */
    wasm_store, /* store ops */
    wasm_select, /* "select" */
    wasm_relational, /* comparison ops */
    wasm_eqz, /* "eqz" */
    wasm_current_memory, /* "current_memory" */
    wasm_grow_memory, /* "grow_memory" */
    wasm_signature /* "signature", which isn't an opcode */
  };

enum wasm_signedness
  {
    wasm_signed,
    wasm_unsigned,
    wasm_agnostic,
    wasm_floating
  };

enum wasm_type
  {
    wasm_void,
    wasm_any,
    wasm_i32,
    wasm_i64,
    wasm_f32,
    wasm_f64
  };

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

const char comment_chars[] = ";#";
const char line_comment_chars[] = ";#";
const char line_separator_chars[] = "";

const char *md_shortopts = "m:";

const char EXP_CHARS[] = "eE";
const char FLT_CHARS[] = "dD";

/* The target specific pseudo-ops which we support.  */
const pseudo_typeS md_pseudo_table[] =
{
  { "qi", cons, 1 }, /* 8-bit integer */
  { "hi", cons, 2 }, /* 16-bit integer */
  { "si", cons, 4 }, /* 32-bit integer */
  { "di", cons, 8 }, /* 64-bit integer */
  { "QI", cons, 1 }, /* 8-bit integer */
  { "HI", cons, 2 }, /* 16-bit integer */
  { "SI", cons, 4 }, /* 32-bit integer */
  { "DI", cons, 8 }, /* 64-bit integer */
  { NULL,	NULL,		0}
};

/* Opcode hash table.  */
static struct hash_control *wasm32_hash;

enum options
{
  OPTION_SYMBOLIC_INDEX = OPTION_MD_BASE + 1,
};

struct option md_longopts[] =
{
  { "symbolic-index", no_argument, NULL, OPTION_SYMBOLIC_INDEX },
  { NULL, no_argument, NULL, 0 }
};

size_t md_longopts_size = sizeof (md_longopts);

int
md_estimate_size_before_relax (fragS *fragp ATTRIBUTE_UNUSED,
                               asection *seg ATTRIBUTE_UNUSED)
{
  abort ();
  return 0;
}

void
md_show_usage (FILE *stream)
{
  fprintf (stream,
      _("WASM32 Assembler options:\n"
        "  symbolic-index         use symbolic rather than numeric indices\n"
        ));
}

int
md_parse_option (int c ATTRIBUTE_UNUSED, const char *arg ATTRIBUTE_UNUSED)
{
  return 0;
}

symbolS *
md_undefined_symbol (char *name ATTRIBUTE_UNUSED)
{
  return NULL;
}

const char *
md_atof (int type, char *litP, int *sizeP)
{
  return ieee_md_atof (type, litP, sizeP, FALSE);
}

void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED,
                 asection *sec ATTRIBUTE_UNUSED,
                 fragS *fragP ATTRIBUTE_UNUSED)
{
  abort ();
}

void
md_begin (void)
{
  struct wasm32_opcode_s *opcode;

  wasm32_hash = hash_new ();

  /* Insert unique names into hash table.  This hash table then provides a
     quick index to the first opcode with a particular name in the opcode
     table.  */
  for (opcode = wasm32_opcodes; opcode->name; opcode++)
    hash_insert (wasm32_hash, opcode->name, (char *) opcode);

  linkrelax = 0;
  flag_sectname_subst = 1;
  flag_no_comments = 0;
  flag_keep_locals = 1;
}

/* GAS will call this function for each section at the end of the assembly,
   to permit the CPU backend to adjust the alignment of a section.  */

valueT
md_section_align (asection *seg, valueT addr)
{
  int align = bfd_get_section_alignment (stdoutput, seg);
  return ((addr + (1 << align) - 1) & -(1 << align));
}

/* If you define this macro, it should return the offset between the
   address of a PC relative fixup and the position from which the PC
   relative adjustment should be made.  On many processors, the base
   of a PC relative instruction is the next instruction, so this
   macro would return the length of an instruction.  */

long
md_pcrel_from_section (fixS *fixp ATTRIBUTE_UNUSED, segT sec ATTRIBUTE_UNUSED)
{
  return 0;
}

int
wasm32_validate_fix_sub (fixS *fix ATTRIBUTE_UNUSED)
{
  return 1;
}

/* TC_FORCE_RELOCATION hook */

/* GAS will call this for each fixup.  It should store the correct
   value in the object file.  */

static void
apply_full_field_fix (fixS *fixP, char *buf ATTRIBUTE_UNUSED, bfd_vma val, int size ATTRIBUTE_UNUSED)
{
  if (fixP->fx_addsy != NULL || fixP->fx_pcrel)
    {
      fixP->fx_addnumber = val;

      return;
    }
  number_to_chars_littleendian (buf, val, size);
}

void
md_apply_fix (fixS *fixP, valueT * valP ATTRIBUTE_UNUSED, segT seg ATTRIBUTE_UNUSED)
{
  char *buf = fixP->fx_where + fixP->fx_frag->fr_literal;
  long val = (long) *valP;


  if (fixP->fx_pcrel)
    {
      switch (fixP->fx_r_type)
        {
        default:
          bfd_set_error (bfd_error_bad_value);
          return;

        case BFD_RELOC_32:
          fixP->fx_r_type = BFD_RELOC_32_PCREL;
          return;
        }
    }

  switch (fixP->fx_r_type)
    {
    default:
      apply_full_field_fix (fixP, buf, val, fixP->fx_size);
      break;
    }

  if (fixP->fx_addsy == 0 && fixP->fx_pcrel == 0)
    fixP->fx_done = 1;
}

static inline char *
skip_space (char *s)
{
  while (*s == ' ' || *s == '\t')
    ++s;
  return s;
}

static char *
extract_word (char *from, char *to, int limit)
{
  char *op_end;
  int size = 0;

  /* Drop leading whitespace.  */
  from = skip_space (from);
  *to = 0;

  /* Find the op code end.  */
  for (op_end = from; *op_end != 0 && is_part_of_name (*op_end);)
    {
      to[size++] = *op_end++;
      if (size + 1 >= limit)
	break;
    }

  to[size] = 0;
  return op_end;
}

static void wasm32_put_long_uleb128(int bits, unsigned long value)
{
  unsigned char c;
  int i = 0;

  do {
    c = value & 0x7f;
    value >>= 7;
    if (i < (bits-1)/7)
      c |= 0x80;
    FRAG_APPEND_1_CHAR (c);
  } while (++i < (bits+6)/7);
}

static void wasm32_put_sleb128(long value)
{
  unsigned char c;
  int more;

  do {
    c = (value & 0x7f);
    value >>= 7;
    more = !((((value == 0) && ((c & 0x40) == 0))
              || ((value == -1) && ((c & 0x40) != 0))));
    if (more)
      c |= 0x80;
    FRAG_APPEND_1_CHAR (c);
  } while (more);
}

static void wasm32_put_uleb128(unsigned long value)
{
  unsigned char c;

  do {
    c = value & 0x7f;
    value >>= 7;
    if (value)
      c |= 0x80;
    FRAG_APPEND_1_CHAR (c);
  } while (value);
}

static void wasm32_leb128(char **line, int bits, int sign)
{
  char *t = input_line_pointer;
  char *str = *line;
  struct reloc_list *reloc;
  expressionS ex;
  int gotrel = 0;
  int pltrel = 0;
  int code = 0;

  input_line_pointer = str;
  expression (&ex);

  if (ex.X_op == O_constant && strncmp(input_line_pointer, "@", 1))
    {
      unsigned long value = ex.X_add_number;

      str = input_line_pointer;
      str = skip_space (str);
      *line = str;
      if (sign)
        wasm32_put_sleb128(value);
      else
        wasm32_put_uleb128(value);
      input_line_pointer = t;
      return;
    }

  reloc = XNEW (struct reloc_list);
  reloc->u.a.offset_sym = expr_build_dot ();
  if (ex.X_op == O_symbol)
    {
      reloc->u.a.sym = ex.X_add_symbol;
      reloc->u.a.addend = ex.X_add_number;
    }
  else
    {
      reloc->u.a.sym = make_expr_symbol (&ex);
      reloc->u.a.addend = 0;
    }
  if (strncmp(input_line_pointer, "@gotcode", 8) == 0) {
    gotrel = 1;
    code = 1;
    input_line_pointer += 8;
  }
  if (strncmp(input_line_pointer, "@got", 4) == 0) {
    gotrel = 1;
    input_line_pointer += 4;
  }
  if (strncmp(input_line_pointer, "@plt", 4) == 0) {
    pltrel = 1;
    code = 1;
    input_line_pointer += 4;
  }
  reloc->u.a.howto = bfd_reloc_name_lookup (stdoutput,
                                            gotrel ? (code ? "R_ASMJS_LEB128_GOT_CODE" : "R_ASMJS_LEB128_GOT") :
                                            pltrel ? "R_ASMJS_LEB128_PLT" :
                                            "R_ASMJS_LEB128");
  if (!reloc->u.a.howto)
    {
      as_bad (_("couldn't find relocation to use"));
    }
  reloc->file = as_where (&reloc->line);
  reloc->next = reloc_list;
  reloc_list = reloc;

  str = input_line_pointer;
  str = skip_space (str);
  *line = str;
  wasm32_put_long_uleb128(bits, 0);
  input_line_pointer = t;
}

static void wasm32_uleb128(char **line, int bits)
{
  wasm32_leb128(line, bits, 0);
}

static void wasm32_sleb128(char **line, int bits)
{
  wasm32_leb128(line, bits, 1);
}

static void wasm32_f32(char **line)
{
  char *t = input_line_pointer;
  input_line_pointer = *line;
  float_cons('f');
  *line = input_line_pointer;
  input_line_pointer = t;
}

static void wasm32_f64(char **line)
{
  char *t = input_line_pointer;
  input_line_pointer = *line;
  float_cons('d');
  *line = input_line_pointer;
  input_line_pointer = t;
}

static void wasm32_signature(char **line)
{
  unsigned long count = 0;
  char *str = *line;
  char *ostr;
  char *result;
  if (*str++ != 'F')
    as_bad (_("Not a function type"));
  result = str;
  ostr = str + 1;
  str++;
  while (*str != 'E') {
    switch (*str++) {
    case 'i':
    case 'l':
    case 'f':
    case 'd':
      count++;
      break;
    default:
      as_bad (_("Unknown type %c\n"), str[-1]);
    }
  }
  wasm32_put_uleb128(count);
  str = ostr;
  while (*str != 'E') {
    switch (*str++) {
    case 'i':
      FRAG_APPEND_1_CHAR(0x7f);
      break;
    case 'l':
      FRAG_APPEND_1_CHAR(0x7e);
      break;
    case 'f':
      FRAG_APPEND_1_CHAR(0x7d);
      break;
    case 'd':
      FRAG_APPEND_1_CHAR(0x7c);
      break;
    default:
      as_bad (_("Unknown type"));
    }
  }
  str++;
  switch (*result) {
  case 'v':
    FRAG_APPEND_1_CHAR(0x00);
    break;
  case 'i':
    FRAG_APPEND_1_CHAR(0x01);
    FRAG_APPEND_1_CHAR(0x7f);
    break;
  case 'l':
    FRAG_APPEND_1_CHAR(0x01);
    FRAG_APPEND_1_CHAR(0x7e);
    break;
  case 'f':
    FRAG_APPEND_1_CHAR(0x01);
    FRAG_APPEND_1_CHAR(0x7d);
    break;
  case 'd':
    FRAG_APPEND_1_CHAR(0x01);
    FRAG_APPEND_1_CHAR(0x7c);
    break;
  default:
    as_bad (_("Unknown type"));
  }
  *line = str;
}

static unsigned
wasm32_operands (struct wasm32_opcode_s *opcode, char **line)
{
  char *str = *line;
  unsigned long block_type = 0;
  FRAG_APPEND_1_CHAR (opcode->opcode);
  str = skip_space (str);
  if (str[0] == '[')
    {
      str++;
      block_type = 0x40;
      if (str[0] != ']') {
        str = skip_space (str);
        switch (str[0])
          {
          case 'i':
            block_type = 0x7f;
            str++;
            break;
          case 'l':
            block_type = 0x7e;
            str++;
            break;
          case 'f':
            block_type = 0x7d;
            str++;
            break;
          case 'd':
            block_type = 0x7c;
            str++;
            break;
          }
        while (str[0] == ':' || (str[0] >= '0' && str[0] <= '9'))
          str++;
        if (str[0] == ']')
          str++;
        str = skip_space (str);
      }
    }
  switch (opcode->clas)
    {
    case wasm_typed:
      FRAG_APPEND_1_CHAR (block_type);
      break;
    case wasm_drop:
    case wasm_special:
    case wasm_binary:
    case wasm_unary:
    case wasm_relational:
    case wasm_select:
    case wasm_eqz:
    case wasm_conv:
      break;
    case wasm_store:
    case wasm_load:
      if (str[0] == 'a' && str[1] == '=')
        {
          str += 2;
          wasm32_uleb128(&str, 32);
        }
      else
        {
          as_bad (_("missing alignment hint"));
        }
      str = skip_space (str);
      wasm32_uleb128(&str, 32);
      break;
    case wasm_set_local:
    case wasm_get_local:
    case wasm_tee_local:
      wasm32_uleb128(&str, 32);
      break;
    case wasm_break:
    case wasm_break_if:
      wasm32_uleb128(&str, 32);
      break;
    case wasm_current_memory:
    case wasm_grow_memory:
      wasm32_uleb128(&str, 32);
      break;
    case wasm_return:
      break;
    case wasm_call:
      wasm32_uleb128(&str, 32);
      break;
    case wasm_call_indirect:
      wasm32_uleb128(&str, 32);
      wasm32_uleb128(&str, 32);
      break;
    case wasm_constant_i32:
      wasm32_sleb128(&str, 32);
      break;
    case wasm_constant_i64:
      wasm32_sleb128(&str, 64);
      break;
    case wasm_constant_f32:
      wasm32_f32(&str);
      break;
    case wasm_constant_f64:
      wasm32_f64(&str);
      break;
    case wasm_break_table:
      {
        do {
          wasm32_uleb128(&str, 32);
          str = skip_space (str);
        } while (str[0]);

        break;
      }
    case wasm_signature:
      wasm32_signature(&str);
    }
  str = skip_space (str);

  *line = str;

  return 0;
}

void
md_assemble (char *str)
{
  char op[32];
  char *t;
  struct wasm32_opcode_s *opcode;

  str = skip_space (extract_word (str, op, sizeof (op)));

  if (!op[0])
    as_bad (_("can't find opcode "));

  opcode = (struct wasm32_opcode_s *) hash_find (wasm32_hash, op);

  if (opcode == NULL)
    {
      as_bad (_("unknown opcode `%s'"), op);
      return;
    }

  dwarf2_emit_insn (0);

  t = input_line_pointer;
  wasm32_operands (opcode, &str);
  input_line_pointer = t;
}

void
tc_cfi_frame_initial_instructions (void)
{
}

bfd_boolean
wasm32_allow_local_subtract (expressionS * left ATTRIBUTE_UNUSED,
                             expressionS * right ATTRIBUTE_UNUSED,
                             segT section ATTRIBUTE_UNUSED)
{
  return TRUE;
}

/* This hook is called when alignment is performed, and allows us to
   capture the details of both .org and .align directives.  */

void
wasm32_handle_align (fragS *fragP ATTRIBUTE_UNUSED)
{
}

void
wasm32_post_relax_hook (void)
{
}

void wasm32_elf_final_processing (void)
{
}

int
wasm32_force_relocation (fixS *f ATTRIBUTE_UNUSED)
{
  if (f->fx_r_type == BFD_RELOC_ASMJS_LEB128_PLT ||
      f->fx_r_type == BFD_RELOC_ASMJS_LEB128_GOT)
    return 1;

  return 0;
}

bfd_boolean wasm32_fix_adjustable (fixS * fixP)
{
  if (fixP->fx_addsy == NULL)
    return TRUE;

  if (fixP->fx_r_type == BFD_RELOC_ASMJS_LEB128_PLT ||
      fixP->fx_r_type == BFD_RELOC_ASMJS_LEB128_GOT)
    return FALSE;

  return TRUE;
}

arelent **
tc_gen_reloc (asection *sec ATTRIBUTE_UNUSED,
              fixS *fixp)
{
  arelent **ret;
  arelent *reloc;

  ret = xmalloc(3 * sizeof (* ret));
  ret[1] = ret[2] = NULL;

  reloc = (arelent *) xmalloc (sizeof (* reloc));
  reloc->sym_ptr_ptr = (asymbol **) xmalloc (sizeof (asymbol *));
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;

  ret[0] = reloc;

  /* Make sure none of our internal relocations make it this far.
     They'd better have been fully resolved by this point.  */
  gas_assert ((int) fixp->fx_r_type > 0);

  reloc->howto = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  if (reloc->howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
                    _("cannot represent `%s' relocation in object file"),
                    bfd_get_reloc_code_name (fixp->fx_r_type));
      return NULL;
    }

  reloc->addend = fixp->fx_offset;

  return ret;
}

void wasm32_start_line_hook (void)
{
}
