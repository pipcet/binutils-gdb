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
#include "elf/asmjs.h"

/* FIXME: Belongs in global header.  */
#ifndef strneq
#define strneq(a,b,n)	(strncmp ((a), (b), (n)) == 0)
#endif

#ifndef NUM_ELEM
#define NUM_ELEM(a)     (sizeof (a) / sizeof (a)[0])
#endif



static void
print_insn_asmjsl (bfd_vma pc ATTRIBUTE_UNUSED,
                  struct disassemble_info *info,
                  unsigned long off0, unsigned long off1)
{
  fprintf_ftype func = info->fprintf_func;
  unsigned long off;

  if (off1 - off0 >= 1024)
    return;

  func (info->stream, "\n");
  for (off = off0; off < off1; off++) {
    unsigned char b[1];
    int status;

    status = info->read_memory_func (off, (bfd_byte *) b, 1, info);
    if (status)
      return;
    func (info->stream, "%c", b[0]);
  }
}

/* Print data bytes on INFO->STREAM.  */

static void
print_insn_data (bfd_vma pc ATTRIBUTE_UNUSED,
		 struct disassemble_info *info,
		 unsigned long given, unsigned long ign ATTRIBUTE_UNUSED)
{
  switch (info->bytes_per_chunk)
    {
    case 1:
      info->fprintf_func (info->stream, ".byte\t0x%02lx", given);
      break;
    case 2:
      info->fprintf_func (info->stream, ".short\t0x%04lx", given);
      break;
    case 4:
      info->fprintf_func (info->stream, ".word\t0x%08lx", given);
      break;
    default:
      abort ();
    }
}

bfd_boolean
asmjs_symbol_is_valid (asymbol * sym,
                       struct disassemble_info * info ATTRIBUTE_UNUSED);
bfd_boolean
asmjs_symbol_is_valid (asymbol * sym,
		     struct disassemble_info * info ATTRIBUTE_UNUSED)
{
  if (sym == NULL)
    return FALSE;

  return TRUE;
}

/* Parse an individual disassembler option.  */

void
parse_asmjs_disassembler_option (const char *option);
void
parse_asmjs_disassembler_option (const char *option)
{
  if (option == NULL)
    return;

  /* XXX - should break 'option' at following delimiter.  */
  fprintf (stderr, _("Unrecognised disassembler option: %s\n"), option);

  return;
}

/* Parse the string of disassembler options, spliting it at whitespaces
   or commas.  (Whitespace separators supported for backwards compatibility).  */

static void
parse_disassembler_options (const char *options)
{
  if (options == NULL)
    return;

  while (*options)
    {
      parse_asmjs_disassembler_option (options);

      /* Skip forward to next seperator.  */
      while ((*options) && (! ISSPACE (*options)) && (*options != ','))
	++ options;
      /* Skip forward past seperators.  */
      while (ISSPACE (*options) || (*options == ','))
	++ options;
    }
}

/* NOTE: There are no checks in these routines that
   the relevant number of data bytes exist.  */

static int
print_insn (bfd_vma pc, struct disassemble_info *info, bfd_boolean little)
{
  unsigned char b[4];
  unsigned long	off0, off1, given;
  int           status;
  int           is_data = FALSE;
  unsigned int	size = 4;
  void	 	(*printer) (bfd_vma, struct disassemble_info *, unsigned long, unsigned long);

  if (info->disassembler_options)
    {
      parse_disassembler_options (info->disassembler_options);

      /* To avoid repeated parsing of these options, we remove them here.  */
      info->disassembler_options = NULL;
    }

  info->bytes_per_line = 16;

  if (is_data && ((info->flags & DISASSEMBLE_DATA) == 0))
    {
      int i;

      /* Size was already set above.  */
      info->bytes_per_chunk = size;
      printer = print_insn_data;

      status = info->read_memory_func (pc, (bfd_byte *) b, size, info);
      given = 0;
      if (little)
	for (i = size - 1; i >= 0; i--)
	  given = b[i] | (given << 8);
      else
	for (i = 0; i < (int) size; i++)
	  given = b[i] | (given << 8);
    }
  else
    {
      printer = print_insn_asmjsl;
      info->bytes_per_chunk = 16;
      size = 16;

      status = info->read_memory_func (pc, (bfd_byte *) b, 4, info);
      off0 = (b[0]) | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
      status = info->read_memory_func (pc+8, (bfd_byte *) b, 4, info);
      off1 = (b[0]) | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
      off0 &= 0xffffffff;
      off1 &= 0xffffffff;
    }

  if (status)
    {
      info->memory_error_func (status, pc, info);
      return -1;
    }

  printer (pc, info, off0, off1);

  return size;
}

int
print_insn_little_asmjs (bfd_vma pc, struct disassemble_info *info);
int
print_insn_little_asmjs (bfd_vma pc, struct disassemble_info *info)
{
  return print_insn (pc, info, TRUE);
}

void print_asmjs_disassembler_options(FILE *);
void
print_asmjs_disassembler_options (FILE *stream)
{
  fprintf (stream, _("\n\
The following ASMJS specific disassembler options are supported for use with\n\
the -M switch:\nnone\n"));
}
