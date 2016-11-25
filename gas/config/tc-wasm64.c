/* tc-wasm64.c -- "Assembler" code for the asm.js target

   Copyright (C) 1999-2015 Free Software Foundation, Inc.
   Copyright (C) 2016 Pip Cet <pipcet@gmail.com>

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
#include "elf/wasm64.h"

enum wasm_clas { wasm_typed, wasm_special, wasm_special1, wasm_break, wasm_break_if, wasm_break_table,
                 wasm_return, wasm_call, wasm_call_import, wasm_call_indirect, wasm_get_local, wasm_set_local, wasm_tee_local, wasm_drop,
wasm_constant, wasm_constant_f32, wasm_constant_f64, wasm_unary, wasm_binary,
wasm_conv, wasm_load, wasm_store, wasm_select, wasm_relational, wasm_eqz, wasm_signature };

enum wasm_signedness { wasm_signed, wasm_unsigned, wasm_agnostic, wasm_floating };

enum wasm_type { wasm_void, wasm_any, wasm_i32, wasm_i64, wasm_f32, wasm_f64 };

#define WASM_OPCODE(name, intype, outtype, clas, signedness, opcode) \
  { name, wasm_ ## intype, wasm_ ## outtype, wasm_ ## clas, wasm_ ## signedness, opcode },

struct wasm64_opcode_s {
  const char *name;
  enum wasm_type intype;
  enum wasm_type outtype;
  enum wasm_clas clas;
  enum wasm_signedness signedness;
  unsigned char opcode;
} wasm64_opcodes[] = {
#include "opcode/wasm.h"
  { NULL, 0, 0, 0, 0, 0 }
};

const char comment_chars[] = ";#";
const char line_comment_chars[] = ";#";
const char line_separator_chars[] = "";

const char *md_shortopts = "m:";

/* WASM64 target-specific switches.  */
struct wasm64_opt_s
{
  int all_opcodes;  /* -mall-opcodes: accept all known WASM64 opcodes.  */
  int no_skip_bug;  /* -mno-skip-bug: no warnings for skipping 2-word insns.  */
  int no_wrap;      /* -mno-wrap: reject rjmp/rcall with 8K wrap-around.  */
  int no_link_relax;   /* -mno-link-relax / -mlink-relax: generate (or not)
                          relocations for linker relaxation.  */
};

static struct wasm64_opt_s wasm64_opt = { 0, 0, 0, 0 };

const char EXP_CHARS[] = "eE";
const char FLT_CHARS[] = "dD";

/* The target specific pseudo-ops which we support.  */
const pseudo_typeS md_pseudo_table[] =
{
  { "qi", cons, 1 },
  { "hi", cons, 2 },
  { "si", cons, 4 },
  { "di", cons, 8 },
  { "QI", cons, 1 },
  { "HI", cons, 2 },
  { "SI", cons, 4 },
  { "DI", cons, 8 },
  { NULL,	NULL,		0}
};

/* Opcode hash table.  */
static struct hash_control *wasm64_hash;

enum options
{
  OPTION_ALL_OPCODES = OPTION_MD_BASE + 1,
  OPTION_NO_SKIP_BUG,
  OPTION_NO_WRAP,
  OPTION_LINK_RELAX,
  OPTION_NO_LINK_RELAX,
  OPTION_INCLUDE,
};

struct option md_longopts[] =
{
  { "isystem", required_argument, NULL, OPTION_INCLUDE },
  { "isysroot", required_argument, NULL, OPTION_INCLUDE },
  { "iprefix", required_argument, NULL, OPTION_INCLUDE },
  { "imultilib", required_argument, NULL, OPTION_INCLUDE },
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
      _("WASM64 Assembler options:\n"
        "None so far.\n"));
}

int
md_parse_option (int c, const char *arg)
{
  switch (c)
    {
    case OPTION_INCLUDE:
      add_include_dir ((char *)arg);
      return 1;
    }

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
  struct wasm64_opcode_s *opcode;

  wasm64_hash = hash_new ();

  /* Insert unique names into hash table.  This hash table then provides a
     quick index to the first opcode with a particular name in the opcode
     table.  */
  for (opcode = wasm64_opcodes; opcode->name; opcode++)
    hash_insert (wasm64_hash, opcode->name, (char *) opcode);

  linkrelax = !wasm64_opt.no_link_relax;
  flag_sectname_subst = 1;
  flag_no_comments = 0;
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
wasm64_validate_fix_sub (fixS *fix ATTRIBUTE_UNUSED)
{
  return 1;
}

/* TC_FORCE_RELOCATION hook */

/* GAS will call this for each fixup.  It should store the correct
   value in the object file.  */

static void
apply_full_field_fix (fixS *fixP, char *buf ATTRIBUTE_UNUSED, bfd_vma val, int size ATTRIBUTE_UNUSED)
{
  fixP->fx_addnumber = val;
}

void
md_apply_fix (fixS *fixP, valueT * valP ATTRIBUTE_UNUSED, segT seg ATTRIBUTE_UNUSED)
{
  char *buf = fixP->fx_where + fixP->fx_frag->fr_literal;
  long val = (long) *valP;
  switch (fixP->fx_r_type)
    {
    default:
      apply_full_field_fix (fixP, buf, val, 4);
      break;
    }
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

static expressionS wasm64_get_constant(char **line)
{
  expressionS ex;
  char *str = *line;
  char *t = input_line_pointer;

  str = skip_space (str);
  input_line_pointer = str;
  expression (& ex);
  *line = input_line_pointer;
  input_line_pointer = t;

  if (ex.X_op != O_constant)
    as_bad (_("constant value required"));

  return ex;
}

static void wasm64_put_uleb128(unsigned long value)
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

static void wasm64_put_long_uleb128(void)
{
  unsigned char c;
  int i = 0;
  unsigned long value = 0;

  do {
    c = value & 0x7f;
    value >>= 7;
    if (i < 15)
      c |= 0x80;
    FRAG_APPEND_1_CHAR (c);
  } while (++i < 16);
}

static void wasm64_uleb128(char **line)
{
  char *t = input_line_pointer;
  char *str = *line;
  struct reloc_list *reloc;
  expressionS ex;
  reloc = XNEW (struct reloc_list);
  input_line_pointer = str;
  expression (&ex);
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
  reloc->u.a.howto = bfd_reloc_name_lookup (stdoutput, "R_ASMJS_LEB128");
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
  wasm64_put_long_uleb128();
  input_line_pointer = t;
}

static void wasm64_uleb128_r32(char **line)
{
  char *t = input_line_pointer;
  char *str = *line;
  struct reloc_list *reloc;
  expressionS ex;
  reloc = XNEW (struct reloc_list);
  input_line_pointer = str;
  expression (&ex);
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
  reloc->u.a.howto = bfd_reloc_name_lookup (stdoutput, "R_ASMJS_LEB128_R32");
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
  wasm64_put_long_uleb128();
  input_line_pointer = t;
}

static void wasm64_u32(char **line)
{
  char *t = input_line_pointer;
  input_line_pointer = *line;
  cons (4);
  *line = input_line_pointer;
  input_line_pointer = t;
}

static void wasm64_f32(char **line)
{
  char *t = input_line_pointer;
  input_line_pointer = *line;
  float_cons('f');
  *line = input_line_pointer;
  input_line_pointer = t;
}

static void wasm64_f64(char **line)
{
  char *t = input_line_pointer;
  input_line_pointer = *line;
  float_cons('d');
  *line = input_line_pointer;
  input_line_pointer = t;
}

static void wasm64_signature(char **line)
{
#if 1
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
  FRAG_APPEND_1_CHAR (count);
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
#else
  unsigned long count = 0;
  char *str = *line;
  char *ostr = str;
  int has_result = 0;
  while (*str) {
    if (strncmp(str, "i32", 3) == 0)
      count++;
    else if (strncmp(str, "i64", 3) == 0)
      count++;
    else if (strncmp(str, "f32", 3) == 0)
      count++;
    else if (strncmp(str, "f64", 3) == 0)
      count++;
    else if (strncmp(str, "result", 6) == 0) {
      count--;
      str += 3;
      has_result = 1;
    }
    str += 3;
    str = skip_space (str);
  }
  FRAG_APPEND_1_CHAR (count); /* XXX >127 arguments */
  str = ostr;
  while (*str) {
    if (strncmp(str, "i32", 3) == 0)
      FRAG_APPEND_1_CHAR (0x01);
    else if (strncmp(str, "i64", 3) == 0)
      FRAG_APPEND_1_CHAR (0x02);
    else if (strncmp(str, "f32", 3) == 0)
      FRAG_APPEND_1_CHAR (0x03);
    else if (strncmp(str, "f64", 3) == 0)
      FRAG_APPEND_1_CHAR (0x04);
    else if (strncmp(str, "result", 6) == 0) {
      FRAG_APPEND_1_CHAR (0x01);
      str += 3;
    }
    str += 3;
    str = skip_space (str);
  }
  if (!has_result)
    FRAG_APPEND_1_CHAR (0x00);
  *line = str;
#endif
}

static unsigned
wasm64_operands (struct wasm64_opcode_s *opcode, char **line)
{
  char *str = *line;
  unsigned long consumed = 0;
  unsigned long block_type = 0;
  FRAG_APPEND_1_CHAR (opcode->opcode);
  str = skip_space (str);
  if (str[0] == '[')
    {
      consumed = wasm64_get_constant(&str).X_add_number;
      switch (str[0])
        {
        case 'i':
          block_type = 0x7f;
          break;
        case 'l':
          block_type = 0x7e;
          break;
        case 'f':
          block_type = 0x7d;
          break;
        case 'd':
          block_type = 0x7c;
          break;
        case ']':
          block_type = 0x40;
          break;
        }
      str = skip_space (str);
      while (str[0] == ':' || (str[0] >= '0' && str[0] <= '9'))
        str++;
      if (str[0] == ']')
        str++;
      str = skip_space (str);
    }
  switch (opcode->clas)
    {
    case wasm_typed:
      FRAG_APPEND_1_CHAR (block_type);
      break;
    case wasm_drop:
    case wasm_special:
    case wasm_special1:
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
          wasm64_uleb128(&str);
          str++;
        }
      else
        {
          as_bad (_("missing alignment hint"));
        }
      str = skip_space (str);
      wasm64_uleb128(&str);
      break;
    case wasm_set_local:
    case wasm_get_local:
    case wasm_tee_local:
      wasm64_uleb128(&str);
      break;
    case wasm_break:
    case wasm_break_if:
      wasm64_put_uleb128(consumed);
      wasm64_uleb128(&str);
      break;
    case wasm_return:
      wasm64_put_uleb128(consumed);
      break;
    case wasm_call:
      wasm64_uleb128_r32(&str);
      break;
    case wasm_call_indirect:
    case wasm_call_import:
      wasm64_put_uleb128(consumed);
      wasm64_uleb128(&str);
      break;
    case wasm_constant:
      wasm64_uleb128(&str);
      break;
    case wasm_constant_f32:
      wasm64_f32(&str);
      break;
    case wasm_constant_f64:
      wasm64_f64(&str);
      break;
    case wasm_break_table:
      {
        unsigned long count = 0;
        char *pstr = str;
        do {
          wasm64_get_constant(&pstr);
          count++;
          pstr  = skip_space (pstr);
        } while (pstr[0]);

        wasm64_put_uleb128(consumed);
        wasm64_put_uleb128(count);
        count++;
        while (count--)
          {
            wasm64_u32(&str);
            str = skip_space (str);
          }
        break;
      }
    case wasm_signature:
      wasm64_signature(&str);
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
  struct wasm64_opcode_s *opcode;

  str = skip_space (extract_word (str, op, sizeof (op)));

  if (!op[0])
    as_bad (_("can't find opcode "));

  opcode = (struct wasm64_opcode_s *) hash_find (wasm64_hash, op);

  if (opcode == NULL)
    {
      as_bad (_("unknown opcode `%s'"), op);
      return;
    }

  t = input_line_pointer;
  wasm64_operands (opcode, &str);
  //if (*skip_space (str))
  //  as_bad (_("garbage at end of line"));
  input_line_pointer = t;
}

void
tc_cfi_frame_initial_instructions (void)
{
}

bfd_boolean
wasm64_allow_local_subtract (expressionS * left ATTRIBUTE_UNUSED,
                             expressionS * right ATTRIBUTE_UNUSED,
                             segT section ATTRIBUTE_UNUSED)
{
  return TRUE;
}

/* This hook is called when alignment is performed, and allows us to
   capture the details of both .org and .align directives.  */

void
wasm64_handle_align (fragS *fragP ATTRIBUTE_UNUSED)
{
}

void
wasm64_post_relax_hook (void)
{
}

void wasm64_elf_final_processing (void)
{
}

int
wasm64_force_relocation (fixS *f ATTRIBUTE_UNUSED)
{
  return 1;
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

void wasm64_start_line_hook (void)
{
}
