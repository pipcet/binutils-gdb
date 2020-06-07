/* tc-asmjs.c -- "Assembler" code for the asm.js target

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
#include "elf/asmjs.h"

struct asmjs_opcodes_s
{
  char *        name;
  char *        constraints;
  char *        opcode;
  int           insn_size;		/* In words.  */
  int           isa;
  unsigned int  bin_opcode;
};

#define ASMJS_INSN(NAME, CONSTR, OPCODE, SIZE, ISA, BIN) \
{#NAME, CONSTR, OPCODE, SIZE, ISA, BIN},

struct asmjs_opcodes_s asmjs_opcodes[] =
{
  {NULL, NULL, NULL, 0, 0, 0}
};

const char comment_chars[] = "";
const char line_comment_chars[] = "#";
const char line_separator_chars[] = "";

const char *md_shortopts = "m:";

/* ASMJS target-specific switches.  */
struct asmjs_opt_s
{
  int all_opcodes;  /* -mall-opcodes: accept all known ASMJS opcodes.  */
  int no_skip_bug;  /* -mno-skip-bug: no warnings for skipping 2-word insns.  */
  int no_wrap;      /* -mno-wrap: reject rjmp/rcall with 8K wrap-around.  */
  int no_link_relax;   /* -mno-link-relax / -mlink-relax: generate (or not)
                          relocations for linker relaxation.  */
};

static struct asmjs_opt_s asmjs_opt = { 0, 0, 0, 0 };

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
static struct hash_control *asmjs_hash;

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
      _("ASMJS Assembler options:\n"
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
  struct asmjs_opcodes_s *opcode;

  asmjs_hash = hash_new ();

  /* Insert unique names into hash table.  This hash table then provides a
     quick index to the first opcode with a particular name in the opcode
     table.  */
  for (opcode = asmjs_opcodes; opcode->name; opcode++)
    hash_insert (asmjs_hash, opcode->name, (char *) opcode);

  linkrelax = !asmjs_opt.no_link_relax;
  flag_sectname_subst = 1;
  flag_no_comments = 1;
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
asmjs_validate_fix_sub (fixS *fix ATTRIBUTE_UNUSED)
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

void
md_assemble (char *str)
{
  printf ("aborting: %s\n", str);
  abort ();
  char *p;
  int c;

  for (p = str; *p; p++) {
    c = *p;

    if (c == '$' && !p[1])
      ;
    else
      FRAG_APPEND_1_CHAR (c);
  }

  if (c != '$')
    FRAG_APPEND_1_CHAR ('\n');

  input_line_pointer = p;
}

void
tc_cfi_frame_initial_instructions (void)
{
}

bfd_boolean
asmjs_allow_local_subtract (expressionS * left ATTRIBUTE_UNUSED,
                             expressionS * right ATTRIBUTE_UNUSED,
                             segT section ATTRIBUTE_UNUSED)
{
  return TRUE;
}

/* This hook is called when alignment is performed, and allows us to
   capture the details of both .org and .align directives.  */

void
asmjs_handle_align (fragS *fragP ATTRIBUTE_UNUSED)
{
}

void
asmjs_post_relax_hook (void)
{
}

void asmjs_elf_final_processing (void)
{
}

int
asmjs_force_relocation (fixS *f ATTRIBUTE_UNUSED)
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

int is_pseudo_line (void);
int is_pseudo_line (void)
{
  char *p = input_line_pointer;

  while (ISBLANK (*p))
    p++;

  if (*p == '.' || *p == 0 || *p == '\n')
    return 1;

  return 0;
}

int is_label_line (void);
int is_label_line (void)
{
  char *p = input_line_pointer;

  while (ISALNUM (*p) || *p == '.' || *p == '_')
    p++;

  if (*p == ':')
    return 1;

  return 0;
}

int is_noapp_line (void);
int is_noapp_line (void)
{
  return strncmp(input_line_pointer, "#NO_APP\n", strlen("#NO_APP\n")) == 0;
}

int is_comment_line (void);
int is_comment_line (void)
{
  char *p = input_line_pointer;

  while (ISBLANK (*p))
    p++;

  if (*p == '#' || *p == 0 || *p == '\n')
    return 1;

  return 0;
}


void asmjs_start_line_hook (void)
{
  if (!is_pseudo_line () &&
      !is_label_line () &&
      !is_noapp_line () &&
      !is_comment_line ()) {
    char *input = input_line_pointer;
    char *output = xmalloc (strlen(input) * 2 + strlen("\t.ascii \"\\n\"\n\n"));

    char *p = input;
    char *q = output;

    q += sprintf(q, "\n\t.ascii \"");
    while (*p) {
      switch (*p) {
      case '\\':
        *q++ = '\\';
        *q++ = '\\';
        break;
      case '\"':
        *q++ = '\\';
        *q++ = '\"';
        break;
      case '\n':
        *q++ = '\\';
        *q++ = 'n';
        p++;
        goto out;
      case '$':
        if (p[1] == '\n') {
          p+=2;
          goto out;
        }
        /* fall through */
      default:
        *q++ = *p;
        break;
      }
      p++;
    }
  out:
    q += sprintf(q, "\"\n\n");
    *q++ = 0;

    bump_line_counters (); // XXX work out why this is needed
    input_line_pointer = p;
    input_scrub_insert_line (output);
    free (output);
  }
}
