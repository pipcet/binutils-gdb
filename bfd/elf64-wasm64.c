/* 64-bit ELF for the asm.js target
   Copyright (C) 1999-2015 Free Software Foundation, Inc.
   Copyright (C) 2016 Pip Cet <pipcet@gmail.com>

   This file is NOT part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "bfd_stdint.h"

#include "bfd_stdint.h"
#include "elf-bfd.h"
#include "elf-nacl.h"
#include "elf-vxworks.h"
#include "elf/wasm64.h"

#define ELF_ARCH		bfd_arch_wasm64
#define ELF_TARGET_ID		0x4157
#define ELF_MACHINE_CODE	0x4157
#define ELF_MAXPAGESIZE		1

#define TARGET_LITTLE_SYM       wasm64_elf64_vec
#define TARGET_LITTLE_NAME	"elf64-wasm64"

#define elf_info_to_howto                    wasm64_elf64_info_to_howto
#define elf_backend_can_gc_sections          1
#define elf_backend_rela_normal              1

#define bfd_elf64_bfd_reloc_type_lookup wasm64_elf64_bfd_reloc_type_lookup
#define bfd_elf64_bfd_reloc_name_lookup wasm64_elf64_bfd_reloc_name_lookup

/* ELF relocs are against symbols.  If we are producing relocatable
   output, and the reloc is against an external symbol, and nothing
   has given us any additional addend, the resulting reloc will also
   be against the same symbol.  In such a case, we don't want to
   change anything about the way the reloc is handled, since it will
   all be done at final link time.  Rather than put special case code
   into bfd_perform_relocation, all the reloc types use this howto
   function.  It just short circuits the reloc if producing
   relocatable output against an external symbol.  */

bfd_reloc_status_type
wasm64_elf64_hex16_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                          arelent *reloc_entry,
                          asymbol *symbol,
                          void *data ATTRIBUTE_UNUSED,
                          asection *input_section,
                          bfd *output_bfd,
                          char **error_message ATTRIBUTE_UNUSED);

bfd_reloc_status_type
wasm64_elf64_hex16_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                          arelent *reloc_entry,
                          asymbol *symbol,
                          void *data ATTRIBUTE_UNUSED,
                          asection *input_section,
                          bfd *output_bfd,
                          char **error_message ATTRIBUTE_UNUSED)
{
  bfd_vma relocation;
  bfd_reloc_status_type flag = bfd_reloc_ok;
  bfd_size_type octets;
  bfd_vma output_base = 0;
  reloc_howto_type *howto = reloc_entry->howto;
  asection *reloc_target_output_section;

  if (output_bfd != NULL
      && (symbol->flags & BSF_SECTION_SYM) == 0
      && (! reloc_entry->howto->partial_inplace
          || reloc_entry->addend == 0))
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  /* PR 17512: file: 0f67f69d.  */
  if (howto == NULL)
    return bfd_reloc_undefined;

  /* If we are not producing relocatable output, return an error if
     the symbol is not defined.  An undefined weak symbol is
     considered to have a value of zero (SVR4 ABI, p. 4-27).  */
  if (bfd_is_und_section (symbol->section)
      && (symbol->flags & BSF_WEAK) == 0
      && output_bfd == NULL)
    flag = bfd_reloc_undefined;

  /* Is the address of the relocation really within the section?
     Include the size of the reloc in the test for out of range addresses.
     PR 17512: file: c146ab8b, 46dff27f, 38e53ebf.  */
  octets = reloc_entry->address * bfd_octets_per_byte (abfd);
  if (octets + bfd_get_reloc_size (howto)
      > bfd_get_section_limit_octets (abfd, input_section))
    return bfd_reloc_outofrange;

  /* Get symbol value.  (Common symbols are special.)  */
  if (bfd_is_com_section (symbol->section))
    relocation = 0;
  else
    relocation = symbol->value;

  reloc_target_output_section = symbol->section->output_section;

  /* Convert input-section-relative symbol value to absolute.  */
  if ((output_bfd && ! howto->partial_inplace)
      || reloc_target_output_section == NULL)
    output_base = 0;
  else
    output_base = reloc_target_output_section->vma;

  relocation += output_base + symbol->section->output_offset;

  /* Add in supplied addend.  */
  relocation += reloc_entry->addend;

  /* Here the variable relocation holds the final address of the
     symbol we are relocating against, plus any addend.  */

  if (output_bfd != NULL)
    {
      if (! howto->partial_inplace)
        {
          /* This is a partial relocation, and we want to apply the relocation
             to the reloc entry rather than the raw data. Modify the reloc
             inplace to reflect what we now know.  */
          reloc_entry->addend = relocation;
          reloc_entry->address += input_section->output_offset;
          return flag;
        }
      else
        {
          /* This is a partial relocation, but inplace, so modify the
             reloc record a bit.

             If we've relocated with a symbol with a section, change
             into a ref to the section belonging to the symbol.  */

          reloc_entry->address += input_section->output_offset;

          reloc_entry->addend = relocation;
        }
    }

  relocation >>= howto->rightshift;

  if (howto->complain_on_overflow != complain_overflow_dont
      && flag == bfd_reloc_ok)
    flag = bfd_check_overflow (howto->complain_on_overflow,
                               howto->bitsize,
                               howto->rightshift,
                               bfd_arch_bits_per_address (abfd),
                               relocation);

  {
    unsigned long long value = relocation;
    char buf[17];
    int len;
    int i;

    memset(buf, ' ', 16);
    len = snprintf(buf, 17, "%llx", value);
    if (len < 0 || len > 16)
      return bfd_reloc_outofrange;
    buf[len] = ' ';

    for (i = 0; i < 16; i++) {
      bfd_put_8 (abfd, buf[i], data + octets + i);
    }
  }

  return flag;
}

bfd_reloc_status_type
wasm64_elf64_leb128_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                          arelent *reloc_entry,
                          asymbol *symbol,
                          void *data ATTRIBUTE_UNUSED,
                          asection *input_section,
                          bfd *output_bfd,
                          char **error_message ATTRIBUTE_UNUSED);

bfd_reloc_status_type
wasm64_elf64_leb128_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                           arelent *reloc_entry,
                           asymbol *symbol,
                           void *data ATTRIBUTE_UNUSED,
                           asection *input_section,
                           bfd *output_bfd,
                           char **error_message ATTRIBUTE_UNUSED)
{
  bfd_vma relocation;
  bfd_reloc_status_type flag = bfd_reloc_ok;
  bfd_size_type octets;
  bfd_vma output_base = 0;
  reloc_howto_type *howto = reloc_entry->howto;
  asection *reloc_target_output_section;

  if (output_bfd != NULL
      && (symbol->flags & BSF_SECTION_SYM) == 0
      && (! reloc_entry->howto->partial_inplace
          || reloc_entry->addend == 0))
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  /* PR 17512: file: 0f67f69d.  */
  if (howto == NULL)
    return bfd_reloc_undefined;

  /* If we are not producing relocatable output, return an error if
     the symbol is not defined.  An undefined weak symbol is
     considered to have a value of zero (SVR4 ABI, p. 4-27).  */
  if (bfd_is_und_section (symbol->section)
      && (symbol->flags & BSF_WEAK) == 0
      && output_bfd == NULL)
    flag = bfd_reloc_undefined;

  /* Is the address of the relocation really within the section?
     Include the size of the reloc in the test for out of range addresses.
     PR 17512: file: c146ab8b, 46dff27f, 38e53ebf.  */
  octets = reloc_entry->address * bfd_octets_per_byte (abfd);
  if (octets + bfd_get_reloc_size (howto)
      > bfd_get_section_limit_octets (abfd, input_section))
    return bfd_reloc_outofrange;

  /* Get symbol value.  (Common symbols are special.)  */
  if (bfd_is_com_section (symbol->section))
    relocation = 0;
  else
    relocation = symbol->value;

  reloc_target_output_section = symbol->section->output_section;

  /* Convert input-section-relative symbol value to absolute.  */
  if ((output_bfd && ! howto->partial_inplace)
      || reloc_target_output_section == NULL)
    output_base = 0;
  else
    output_base = reloc_target_output_section->vma;

  relocation += output_base + symbol->section->output_offset;

  /* Add in supplied addend.  */
  relocation += reloc_entry->addend;

  /* Here the variable relocation holds the final address of the
     symbol we are relocating against, plus any addend.  */

  if (output_bfd != NULL)
    {
      if (! howto->partial_inplace)
        {
          /* This is a partial relocation, and we want to apply the relocation
             to the reloc entry rather than the raw data. Modify the reloc
             inplace to reflect what we now know.  */
          reloc_entry->addend = relocation;
          reloc_entry->address += input_section->output_offset;
          return flag;
        }
      else
        {
          /* This is a partial relocation, but inplace, so modify the
             reloc record a bit.

             If we've relocated with a symbol with a section, change
             into a ref to the section belonging to the symbol.  */

          reloc_entry->address += input_section->output_offset;

          reloc_entry->addend = relocation;
        }
    }

  relocation >>= howto->rightshift;

  if (howto->complain_on_overflow != complain_overflow_dont
      && flag == bfd_reloc_ok)
    flag = bfd_check_overflow (howto->complain_on_overflow,
                               howto->bitsize,
                               howto->rightshift,
                               bfd_arch_bits_per_address (abfd),
                               relocation);

  {
    unsigned long long value = relocation;

    int len = 0;
    int i;
    while (bfd_get_8 (abfd, data + octets + len++) & 0x80)
      {
      }

    for (i = 0; i < len-1; i++)
      {
        bfd_put_8 (abfd, 0x80 | (value & 0x7f), data + octets + i);
        value >>= 7;
      }
    bfd_put_8 (abfd, (value & 0x7f), data + octets + i);
  }

  return flag;
}

static reloc_howto_type wasm64_elf64_howto_table[] =
  {
  HOWTO (R_ASMJS_NONE,		/* type */
         0,			/* rightshift */
         3,			/* size (0 = byte, 1 = short, 2 = long) */
         0,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_ASMJS_NONE",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0,			/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_HEX16,		/* type */
         0,			/* rightshift */
         8,			/* size - 16 bytes*/
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm64_elf64_hex16_reloc,/* special_function */
         "R_ASMJS_HEX16",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_HEX16R4,	/* type */
         4,			/* rightshift */
         8,			/* size - 16 bytes*/
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm64_elf64_hex16_reloc,/* special_function */
         "R_ASMJS_HEX16R4",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffffLL,	/* src_mask */
         0xffffffffffffffffLL,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* 32 bit absolute */
  HOWTO (R_ASMJS_ABS32,		/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_ASMJS_ABS32",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffff,		/* src_mask */
         0xffffffff,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* standard 32bit pc-relative reloc */
  HOWTO (R_ASMJS_REL32,		/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         TRUE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_ASMJS_REL32",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffff,		/* src_mask */
         0xffffffff,		/* dst_mask */
         TRUE),			/* pcrel_offset */

    HOWTO (R_ASMJS_HEX16R12,	/* type */
         12,			/* rightshift */
         8,			/* size - 16 bytes*/
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm64_elf64_hex16_reloc,/* special_function */
         "R_ASMJS_HEX16R12",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffffLL,	/* src_mask */
         0xffffffffffffffffLL,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* standard 32bit pc-relative reloc */
  HOWTO (R_ASMJS_REL16,		/* type */
         0,			/* rightshift */
         1,			/* size (0 = byte, 1 = short, 2 = long) */
         16,			/* bitsize */
         TRUE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_ASMJS_REL16",	/* name */
         FALSE,			/* partial_inplace */
         0xffff,		/* src_mask */
         0xffff,		/* dst_mask */
         TRUE),			/* pcrel_offset */

  /* standard 32bit pc-relative reloc */
  HOWTO (R_ASMJS_ABS16,		/* type */
         0,			/* rightshift */
         1,			/* size (0 = byte, 1 = short, 2 = long) */
         16,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_ASMJS_ABS16",	/* name */
         FALSE,			/* partial_inplace */
         0xffff,		/* src_mask */
         0xffff,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* 64 bit absolute */
  HOWTO (R_ASMJS_ABS64,		/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_ASMJS_ABS64",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffffLL,  /* src_mask */
         0xffffffffffffffffLL,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* standard 64bit pc-relative reloc */
  HOWTO (R_ASMJS_REL64,		/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         64,			/* bitsize */
         TRUE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_ASMJS_REL64",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffffLL,	/* src_mask */
         0xffffffffffffffffLL,	/* dst_mask */
         TRUE),			/* pcrel_offset */

  HOWTO (R_ASMJS_LEB128,	/* type */
         0,			/* rightshift */
         8,			/* size - 16 bytes*/
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm64_elf64_leb128_reloc,/* special_function */
         "R_ASMJS_LEB128",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_LEB128R32,	/* type */
         32,			/* rightshift */
         8,			/* size - 16 bytes*/
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm64_elf64_leb128_reloc,/* special_function */
         "R_ASMJS_LEB128_R32",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */
};

reloc_howto_type *
wasm64_elf64_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   const char *r_name);

reloc_howto_type *
wasm64_elf64_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < (sizeof (wasm64_elf64_howto_table)
            / sizeof (wasm64_elf64_howto_table[0]));
       i++)
    if (wasm64_elf64_howto_table[i].name != NULL
        && strcasecmp (wasm64_elf64_howto_table[i].name, r_name) == 0)
      return &wasm64_elf64_howto_table[i];

  return NULL;
}

reloc_howto_type *
wasm64_elf64_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   enum bfd_reloc_code_real code);

reloc_howto_type *
wasm64_elf64_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   enum bfd_reloc_code_real code)
{
  switch (code) {
  case BFD_RELOC_64:
    return wasm64_elf64_bfd_reloc_name_lookup(abfd, "R_ASMJS_ABS64");
  case BFD_RELOC_32:
    return wasm64_elf64_bfd_reloc_name_lookup(abfd, "R_ASMJS_ABS32");
  case BFD_RELOC_16:
    return wasm64_elf64_bfd_reloc_name_lookup(abfd, "R_ASMJS_ABS16");
  default:
    return NULL;
  }
}

reloc_howto_type *
wasm64_elf64_info_to_howto_ptr (unsigned int r_type);

reloc_howto_type *
wasm64_elf64_info_to_howto_ptr (unsigned int r_type)
{
  return &wasm64_elf64_howto_table[r_type];
}

void
wasm64_elf64_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
                              Elf_Internal_Rela *dst);
void
wasm64_elf64_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
                              Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF64_R_TYPE (dst->r_info);

  cache_ptr->howto = wasm64_elf64_info_to_howto_ptr (r_type);
}
#include "elf64-target.h"
