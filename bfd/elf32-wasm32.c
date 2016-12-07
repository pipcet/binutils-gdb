/* 32-bit ELF for the asm.js target
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
#include "elf/wasm32.h"

#define ELF_ARCH		bfd_arch_wasm32
#define ELF_TARGET_ID		0x4157
#define ELF_MACHINE_CODE	0x4157
#define ELF_MAXPAGESIZE		1

#define TARGET_LITTLE_SYM       wasm32_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-wasm32"

#define elf_info_to_howto                    wasm32_elf32_info_to_howto
#define elf_backend_can_gc_sections          1
#define elf_backend_rela_normal              1

#define bfd_elf32_bfd_reloc_type_lookup wasm32_elf32_bfd_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup wasm32_elf32_bfd_reloc_name_lookup

#define ELF_DYNAMIC_INTERPRETER  "/sbin/elf-dynamic-interpreter.so"

enum dyn_section_types
{
  got = 0,
  relgot,
  gotplt,
  dyn,
  plt,
  pltspace,
  pltfun,
  pltfunspace,
  pltidx,
  relplt,
  DYN_SECTION_TYPES_END
};

const char * dyn_section_names[DYN_SECTION_TYPES_END] =
{
  ".got",
  ".rela.got",
  ".got.plt",
  ".dynamic",
  ".wasm.payload.code.plt",
  ".wasm.chars.code.plt",
  ".wasm.payload.function.plt",
  ".wasm.chars.function.plt",
  ".wasm.chars.function_index.plt",
  ".rela.plt"
};

#define ADD_DYNAMIC_SYMBOL(NAME, TAG)					\
  h =  elf_link_hash_lookup (elf_hash_table (info),			\
                             NAME, FALSE, FALSE, FALSE);		\
  if ((h != NULL && (h->ref_regular || h->def_regular)))		\
    if (! _bfd_elf_add_dynamic_entry (info, TAG, 0))			\
      return FALSE;

#define GET_SYMBOL_OR_SECTION(TAG, SYMBOL, SECTION)		\
  case TAG:							\
  if (SYMBOL != NULL)						\
    h = elf_link_hash_lookup (elf_hash_table (info),		\
                              SYMBOL, FALSE, FALSE, TRUE);	\
  else if (SECTION != NULL)					\
    s = bfd_get_linker_section (dynobj, SECTION);		\
  break;

static ATTRIBUTE_UNUSED bfd_boolean
is_reloc_PC_relative (reloc_howto_type *howto)
{
  return (strstr (howto->name, "PC") != NULL) ? TRUE : FALSE;
}

#if 0
static bfd_boolean
is_reloc_for_GOT (reloc_howto_type * howto)
{
  if (strstr (howto->name, "TLS") != NULL)
    return FALSE;
  return (strstr (howto->name, "GOT") != NULL) ? TRUE : FALSE;
}

static bfd_boolean
is_reloc_for_PLT (reloc_howto_type * howto)
{
  return (strstr (howto->name, "PLT") != NULL) ? TRUE : FALSE;
}
#endif

struct wasm32_relocation_data
{
  bfd_signed_vma  reloc_offset;
  bfd_signed_vma  reloc_addend;
  bfd_signed_vma  got_offset_value;

  bfd_signed_vma  sym_value;
  asection *      sym_section;

  reloc_howto_type *howto;

  asection *      input_section;

  bfd_signed_vma  sdata_begin_symbol_vma;
  bfd_boolean     sdata_begin_symbol_vma_set;
  bfd_signed_vma  got_symbol_vma;

  bfd_boolean     should_relocate;

  const char *    symbol_name;
};

struct dynamic_sections
{
  bfd_boolean     initialized;
  asection *      sgot;
  asection *      srelgot;
  asection *      sgotplt;
  asection *      srelgotplt;
  asection *      sdyn;
  asection *      splt;
  asection *      spltspace;
  asection *      spltfun;
  asection *      spltfunspace;
  asection *      spltidx;
  asection *      srelplt;
};

struct wasm32_got_entry
{
  struct wasm32_elf_link_hash_entry *h;
  long gotidx;
};

struct wasm32_got_info
{
  /* The number of global .got entries.  */
  unsigned int global_gotno;
  /* The number of relocations needed for the GOT entries.  */
  unsigned int relocs;
  /* A hash table holding members of the got.  */
  struct htab *got_entries;
};

struct plt_entry
{
  bfd_vma offset;
  bfd_vma function_index;
};

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
wasm32_elf32_hex16_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                          arelent *reloc_entry,
                          asymbol *symbol,
                          void *data ATTRIBUTE_UNUSED,
                          asection *input_section,
                          bfd *output_bfd,
                          char **error_message ATTRIBUTE_UNUSED);

bfd_reloc_status_type
wasm32_elf32_hex16_reloc (bfd *abfd ATTRIBUTE_UNUSED,
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

  unsigned long long value = relocation;

  char buf[17];
  memset(buf, ' ', 16);
  int len = snprintf(buf, 17, "%llx", value);
  if (len < 0 || len > 16)
    return bfd_reloc_outofrange;
  buf[len] = ' ';

  int i;
  for (i = 0; i < 16; i++) {
    bfd_put_8 (abfd, buf[i], data + octets + i);
  }

  return flag;
}

bfd_reloc_status_type
wasm32_elf32_leb128_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                          arelent *reloc_entry,
                          asymbol *symbol,
                          void *data ATTRIBUTE_UNUSED,
                          asection *input_section,
                          bfd *output_bfd,
                          char **error_message ATTRIBUTE_UNUSED);

bfd_reloc_status_type
wasm32_elf32_leb128_reloc (bfd *abfd ATTRIBUTE_UNUSED,
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

  return flag;
}

static inline void set_uleb128 (bfd *abfd, unsigned long long value,
                                bfd_byte *addr)
{
  (void)abfd;
  int len = 0;
  int i;
  while (bfd_get_8 (abfd, addr + len++) & 0x80)
    {
    }

  for (i = 0; i < len-1; i++)
    {
      bfd_put_8 (abfd, 0x80 | (value & 0x7f), addr + i);
      value >>= 7;
    }
  bfd_put_8 (abfd, (value & 0x7f), addr + i);
}

static reloc_howto_type wasm32_elf32_howto_table[] =
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
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_hex16_reloc,/* special_function */
         "R_ASMJS_HEX16",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_HEX16R4,	/* type */
         4,			/* rightshift */
         8,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_hex16_reloc,/* special_function */
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
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_hex16_reloc,/* special_function */
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
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_leb128_reloc,/* special_function */
         "R_ASMJS_LEB128",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_LEB128R32,	/* type */
         32,			/* rightshift */
         8,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_leb128_reloc,/* special_function */
         "R_ASMJS_LEB128_R32",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_LEB128_GOT,	/* type */
         0,			/* rightshift */
         8,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_leb128_reloc,/* special_function */
         "R_ASMJS_LEB128_GOT",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_LEB128_PLT,	/* type */
         0,			/* rightshift */
         8,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_leb128_reloc,/* special_function */
         "R_ASMJS_LEB128_PLT",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  HOWTO (R_ASMJS_LEB128_PLT_INDEX, /* type */
         0,			/* rightshift */
         8,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         wasm32_elf32_leb128_reloc,/* special_function */
         "R_ASMJS_LEB128_PLT_INDEX", /* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

};

reloc_howto_type *
wasm32_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   const char *r_name);

reloc_howto_type *
wasm32_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < (sizeof (wasm32_elf32_howto_table)
            / sizeof (wasm32_elf32_howto_table[0]));
       i++)
    if (wasm32_elf32_howto_table[i].name != NULL
        && strcasecmp (wasm32_elf32_howto_table[i].name, r_name) == 0)
      return &wasm32_elf32_howto_table[i];

  return NULL;
}

reloc_howto_type *
wasm32_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   enum bfd_reloc_code_real code);

reloc_howto_type *
wasm32_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                   enum bfd_reloc_code_real code)
{
  switch (code) {
  case BFD_RELOC_32:
    return wasm32_elf32_bfd_reloc_name_lookup(abfd, "R_ASMJS_ABS32");
  case BFD_RELOC_16:
    return wasm32_elf32_bfd_reloc_name_lookup(abfd, "R_ASMJS_ABS16");
  case BFD_RELOC_ASMJS_LEB128_GOT:
    return wasm32_elf32_bfd_reloc_name_lookup(abfd, "R_ASMJS_LEB128_GOT");
  case BFD_RELOC_ASMJS_LEB128_PLT:
    return wasm32_elf32_bfd_reloc_name_lookup(abfd, "R_ASMJS_LEB128_PLT");
  default:
    return NULL;
  }
}

reloc_howto_type *
wasm32_elf32_info_to_howto_ptr (unsigned int r_type);

reloc_howto_type *
wasm32_elf32_info_to_howto_ptr (unsigned int r_type)
{
  if (r_type > R_ASMJS_LEB128_PLT_INDEX)
    r_type = 0;

  return &wasm32_elf32_howto_table[r_type];
}

void
wasm32_elf32_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
                              Elf_Internal_Rela *dst);
void
wasm32_elf32_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
                              Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE (dst->r_info);

  cache_ptr->howto = wasm32_elf32_info_to_howto_ptr (r_type);
}

/* WASM32 ELF linker hash entry.  */
struct elf_wasm32_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* Track dynamic relocs copied for this symbol.  */
  struct elf_dyn_relocs *dyn_relocs;
};

/* WASM32 ELF linker hash table.  */
struct elf_wasm32_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Short-cuts to get to dynamic linker sections.  */
  asection *srelbss;
};


static struct dynamic_sections
wasm32_create_dynamic_sections (bfd * abfd, struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab;
  bfd    *dynobj;
  struct dynamic_sections ds =
    {
      .initialized = FALSE,
      .sgot = NULL,
      .srelgot = NULL,
      .sgotplt = NULL,
      .srelgotplt = NULL,
      .sdyn = NULL,
      .splt = NULL,
      .spltspace = NULL,
      .srelplt = NULL,
      .spltfun = NULL,
      .spltfunspace = NULL,
      .spltidx = NULL,
    };

  htab = elf_hash_table (info);
  BFD_ASSERT (htab);

  /* Create dynamic sections for relocatable executables so that we
     can copy relocations.  */
  if (! htab->dynamic_sections_created && bfd_link_pic (info))
    {
      if (! _bfd_elf_link_create_dynamic_sections (abfd, info))
        BFD_ASSERT (0);
    }

  dynobj = (elf_hash_table (info))->dynobj;

  if (dynobj)
    {
      ds.sgot = htab->sgot;
      ds.srelgot = htab->srelgot;

      ds.sgotplt = bfd_get_section_by_name (dynobj, ".got.plt");
      ds.srelgotplt = ds.srelplt;

      ds.splt = bfd_get_section_by_name (dynobj, ".wasm.payload.code.plt");
      ds.spltspace = bfd_get_section_by_name (dynobj, ".wasm.chars.code.plt");
      if (ds.spltspace == NULL)
        {
          flagword flags, pltflags;
          flags = (SEC_IN_MEMORY
                   | SEC_LINKER_CREATED);

          pltflags = flags;
          bfd_make_section_anyway_with_flags (dynobj, ".wasm.chars.code.plt", pltflags);
          ds.spltspace = bfd_get_section_by_name (dynobj, ".wasm.chars.code.plt");
        }

      ds.spltfun = bfd_get_section_by_name (dynobj, ".wasm.payload.function.plt");
      ds.spltfunspace = bfd_get_section_by_name (dynobj, ".wasm.chars.function.plt");
      ds.spltidx = bfd_get_section_by_name (dynobj, ".wasm.chars.function_index");
      ds.srelplt = bfd_get_section_by_name (dynobj, ".rela.plt");
    }

  if (htab->dynamic_sections_created)
    {
      ds.sdyn = bfd_get_section_by_name (dynobj, ".dynamic");
    }

  ds.initialized = TRUE;

  return ds;
}

static bfd_vma
add_symbol_to_plt (bfd *output_bfd, struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);
  struct dynamic_sections ds = wasm32_create_dynamic_sections (output_bfd, info);
  bfd_vma ret;

  ret = htab->splt->size;

  htab->splt->size += 0x40;

  htab->sgotplt->size += 4;
  htab->srelplt->size += 2 * sizeof (Elf32_External_Rela);

  ds.spltspace->size++;
  ds.spltfun->size++;
  ds.spltfunspace->size++;
  ds.spltidx->size++;

  return ret;
}

static bfd_boolean
elf_wasm32_adjust_dynamic_symbol (struct bfd_link_info *info,
                              struct elf_link_hash_entry *h)
{
  asection *s;
  bfd *dynobj = (elf_hash_table (info))->dynobj;
  struct elf_link_hash_table *htab = elf_hash_table (info);

  if (h->type == STT_FUNC
      || h->type == STT_GNU_IFUNC
      || h->needs_plt == 1)
    {
      if (!bfd_link_pic (info) && !h->def_dynamic && !h->ref_dynamic)
        {
          /* This case can occur if we saw a PLT32 reloc in an input
             file, but the symbol was never referred to by a dynamic
             object.  In such a case, we don't actually need to build
             a procedure linkage table, and we can just do a PC32
             reloc instead.  */
          BFD_ASSERT (h->needs_plt);
          return TRUE;
        }

      /* Make sure this symbol is output as a dynamic symbol.  */
      if (h->dynindx == -1 && !h->forced_local
          && !bfd_elf_link_record_dynamic_symbol (info, h))
        return FALSE;

      if (bfd_link_pic (info)
          || WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, 0, h))
        {
          bfd_vma loc = add_symbol_to_plt (dynobj, info);

          if (bfd_link_executable (info) && !h->def_regular)
            {
              h->root.u.def.section = htab->splt;
              h->root.u.def.value = loc;
            }
          h->plt.offset = loc;
        }
      else
        {
          h->plt.offset = (bfd_vma) -1;
          h->needs_plt = 0;
        }
      return TRUE;
    }

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the
     real definition first, and we can just use the same value.  */
  if (h->u.weakdef != NULL)
    {
      BFD_ASSERT (h->u.weakdef->root.type == bfd_link_hash_defined
                  || h->u.weakdef->root.type == bfd_link_hash_defweak);
      h->root.u.def.section = h->u.weakdef->root.u.def.section;
      h->root.u.def.value = h->u.weakdef->root.u.def.value;
      return TRUE;
    }

  /* This is a reference to a symbol defined by a dynamic object which
     is not a function.  */

  /* If we are creating a shared library, we must presume that the
     only references to the symbol are via the global offset table.
     For such cases we need not do anything here; the relocations will
     be handled correctly by relocate_section.  */
  if (!bfd_link_executable (info))
    return TRUE;

  /* If there are no non-GOT references, we do not need a copy
     relocation.  */
  if (!h->non_got_ref)
    return TRUE;

  /* If -z nocopyreloc was given, we won't generate them either.  */
  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  /* We must allocate the symbol in our .dynbss section, which will
     become part of the .bss section of the executable.  There will be
     an entry for this symbol in the .dynsym section.  The dynamic
     object will contain position independent code, so all references
     from the dynamic object to this symbol will go through the global
     offset table.  The dynamic linker will use the .dynsym entry to
     determine the address it must put in the global offset table, so
     both the dynamic object and the regular object will refer to the
     same memory location for the variable.  */

  if (htab == NULL)
    return FALSE;

  s = bfd_get_section_by_name (dynobj, ".dynbss");
  BFD_ASSERT (s != NULL);

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

static bfd_boolean
elf_wasm32_check_relocs (bfd *abfd, struct bfd_link_info *info, asection *sec, const Elf_Internal_Rela* relocs) __attribute__((used));

static bfd_boolean
elf_wasm32_check_relocs (bfd *abfd, struct bfd_link_info *info, asection *sec, const Elf_Internal_Rela* relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *	rel;
  const Elf_Internal_Rela *	rel_end;
  bfd *				dynobj;
  asection *			sreloc = NULL;
  bfd_vma *local_got_offsets;
  asection *sgot;
  asection *srelgot;

  if (bfd_link_relocatable (info))
    return TRUE;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);

  local_got_offsets = elf_local_got_offsets (abfd);

  dynobj = (elf_hash_table (info))->dynobj;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      int r_type;
      //reloc_howto_type *howto;
      struct elf_link_hash_entry *h;
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);

      r_type = ELF32_R_TYPE (rel->r_info);

      //howto = wasm32_elf_howto (r_type);

      if (dynobj == NULL
          && (r_type == R_ASMJS_LEB128_PLT ||
              r_type == R_ASMJS_LEB128_GOT))
        {
          dynobj = elf_hash_table (info)->dynobj = abfd;
          if (! _bfd_elf_create_got_section (abfd, info))
            return FALSE;
        }

      if (r_symndx < symtab_hdr->sh_info)
        h = NULL;
      else
        {
          h = sym_hashes[r_symndx - symtab_hdr->sh_info];
          while (h->root.type == bfd_link_hash_indirect
                 || h->root.type == bfd_link_hash_warning)
            h = (struct elf_link_hash_entry *) h->root.u.i.link;

          /* PR15323, ref flags aren't set for references in the same
             object.  */
          h->root.non_ir_ref = 1;
        }

      if (dynobj == NULL)
      switch (r_type)
        {
        case R_ASMJS_LEB128_GOT:
        case R_ASMJS_LEB128_PLT:
          elf_hash_table (info)->dynobj = dynobj = abfd;
          if (! _bfd_elf_create_got_section (dynobj, info))
            return FALSE;
          break;
        default:
          break;
        }

      switch (r_type)
        {
        case R_ASMJS_LEB128_GOT:
          /* This symbol requires a GOT entry. */

          sgot = elf_hash_table (info)->sgot;
          srelgot = elf_hash_table (info)->srelgot;

          BFD_ASSERT (sgot != NULL && srelgot != NULL);

          if (h != NULL)
            {
              if (h->got.offset != (bfd_vma) -1)
                {
                  /* We have already allocated space in the .got.  */
                  break;
                }
              h->got.offset = sgot->size;

              /* Make sure this symbol is output as a dynamic symbol.  */
              if (h->dynindx == -1)
                {
                  if (! bfd_elf_link_record_dynamic_symbol (info, h))
                    return FALSE;
                }

              srelgot->size += sizeof (Elf32_External_Rela);
            }
          else
            {
              /* This is a global offset table entry for a local
                 symbol.  */
              if (local_got_offsets == NULL)
                {
                  size_t size;
                  register unsigned int i;

                  size = symtab_hdr->sh_info * sizeof (bfd_vma);
                  /* Reserve space for both the datalabel and
                     codelabel local GOT offsets.  */
                  size *= 2;
                  local_got_offsets = (bfd_vma *) bfd_alloc (abfd, size);
                  if (local_got_offsets == NULL)
                    return FALSE;
                  elf_local_got_offsets (abfd) = local_got_offsets;
                  for (i = 0; i < symtab_hdr->sh_info; i++)
                    local_got_offsets[i] = (bfd_vma) -1;
                  for (; i < 2 * symtab_hdr->sh_info; i++)
                    local_got_offsets[i] = (bfd_vma) -1;
                }
              {
                if (local_got_offsets[r_symndx] != (bfd_vma) -1)
                  {
                    /* We have already allocated space in the .got.  */
                    break;
                  }
                local_got_offsets[r_symndx] = sgot->size;
              }

              if (bfd_link_pic (info))
                {
                  /* If we are generating a shared object, we need to
                     output a R_SH_RELATIVE reloc so that the dynamic
                     linker can adjust this GOT entry.  */
                  srelgot->size += sizeof (Elf32_External_Rela);
                }
            }

          sgot->size += 4;

          break;


        case R_ASMJS_LEB128_PLT:
          if (h)
            h->needs_plt = 1;
          break;
        default:
            if (bfd_link_pic (info))
              {
                if (sreloc == NULL)
                  {
                    sreloc = _bfd_elf_make_dynamic_reloc_section (sec, dynobj,
                                                                  2, abfd,
                                                                  /*rela*/
                                                                  TRUE);

                    if (sreloc == NULL)
                      return FALSE;
                  }
                sreloc->size += sizeof (Elf32_External_Rela);

              }
        }

      if (r_type == R_ASMJS_LEB128_PLT)
        {
          if (h == NULL)
            continue;
          else
            h->needs_plt = 1;
        }
    }

  return TRUE;
}

static bfd_boolean
elf_wasm32_finish_dynamic_symbol (bfd * output_bfd,
                                  struct bfd_link_info *info,
                                  struct elf_link_hash_entry *h,
                                  Elf_Internal_Sym * sym) __attribute__((used));

static bfd_boolean
elf_wasm32_finish_dynamic_symbol (bfd * output_bfd,
                                  struct bfd_link_info *info,
                                  struct elf_link_hash_entry *h,
                                  Elf_Internal_Sym * sym)
{
  if (h->plt.offset != (bfd_vma) -1)
    {
      asection *splt;
      asection *sgot;
      asection *srel;

      bfd_vma plt_index;
      bfd_vma got_offset;
      Elf_Internal_Rela rel;
      bfd_byte *loc;

      /* This symbol has an entry in the procedure linkage table.  Set
         it up.  */

      BFD_ASSERT (h->dynindx != -1);

      splt = elf_hash_table (info)->splt;
      sgot = elf_hash_table (info)->sgotplt;
      srel = elf_hash_table (info)->srelplt;
      BFD_ASSERT (splt != NULL && sgot != NULL && srel != NULL);

      /* Get the index in the procedure linkage table which
         corresponds to this symbol.  This is the index of this symbol
         in all the symbols for which we are making plt entries. */
      plt_index = h->plt.offset / 0x40;

      /* Get the offset into the .got table of the entry that
         corresponds to this function.  Each .got entry is 4 bytes. */
      got_offset = (plt_index) * 4;

      /* Fill in the entry in the procedure linkage table.  */
      uint8_t pltentry[] = {
        0x3f, 0x01, 0x11, 0x7f,
        0x20, 0x00, 0x20, 0x01, 0x20, 0x02,
        0x20, 0x03, 0x20, 0x04, 0x20, 0x05,
        0x23, 0x01, 0x41, 0x80, 0x80, 0x80,
        0x80, 0x00, 0x6a, 0x11, 0x80, 0x80,
        0x80, 0x80, 0x00, 0x00, 0x0f,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x0b
      };
      memcpy (splt->contents + h->plt.offset, pltentry,
              0x40);

      struct elf_link_hash_entry *h2;
      h2 = elf_link_hash_lookup (elf_hash_table (info),
                                 ".wasm.plt_bias", FALSE, FALSE, TRUE);
      BFD_ASSERT (h2 != NULL);

      set_uleb128 (output_bfd,
                   got_offset/4 + h2->root.u.def.value,
                   splt->contents + h->plt.offset + 19);

      /* Fill in the entry in the global offset table.  */
      bfd_put_32 (output_bfd,
                  (splt->output_section->vma
                   + splt->output_offset
                   + h->plt.offset
                   + 19),
                  sgot->contents + got_offset);

      /* Fill in the entry in the .rela.plt section.  */
      rel.r_offset = (sgot->output_section->vma
                      + sgot->output_offset
                      + got_offset);
      rel.r_info = ELF32_R_INFO (h->dynindx, R_ASMJS_LEB128_PLT);
      rel.r_addend = 0;
      loc = srel->contents + 2 * plt_index * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);

      /* Fill in the entry in the .rela.plt section.  */
      rel.r_offset = got_offset/4 + h2->root.u.def.value;
      rel.r_info = ELF32_R_INFO (h->dynindx, R_ASMJS_LEB128_PLT_INDEX);
      rel.r_addend = 0;
      loc = srel->contents + (2 * plt_index + 1) * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);

      if (!h->def_regular)
        {
          /* Mark the symbol as undefined, rather than as defined in
             the .plt section.  Leave the value alone.  */
          sym->st_shndx = SHN_UNDEF;
        }
      //relocate_plt_for_symbol (output_bfd, info, h);
    }

  if (h->got.offset != (bfd_vma) -1)
    {
      asection *sgot;
      asection *srel;
      Elf_Internal_Rela rel;
      bfd_byte *loc;

      /* This symbol has an entry in the global offset table.  Set it
         up.  */

      sgot = elf_hash_table (info)->sgot;
      srel = elf_hash_table (info)->srelgot;
      BFD_ASSERT (sgot != NULL && srel != NULL);

      rel.r_offset = (sgot->output_section->vma
                      + sgot->output_offset
                      + (h->got.offset &~ 1));

      /* If this is a -Bsymbolic link, and the symbol is defined
         locally, we just want to emit a RELATIVE reloc.  Likewise if
         the symbol was forced to be local because of a version file.
         The entry in the global offset table will already have been
         initialized in the relocate_section function.  */
      if (bfd_link_pic (info)
          && (info->symbolic || h->dynindx == -1)
          && h->def_regular)
        {
          rel.r_info = ELF32_R_INFO (0, R_ASMJS_REL32);
          rel.r_addend = (h->root.u.def.value
                          + h->root.u.def.section->output_section->vma
                          + h->root.u.def.section->output_offset);
        }
      else
        {
          bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + h->got.offset);
          rel.r_info = ELF32_R_INFO (h->dynindx, R_ASMJS_ABS32);
          rel.r_addend = 0;
        }

      loc = srel->contents;
      loc += srel->reloc_count++ * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);
    }


  /* This function traverses list of GOT entries and
     create respective dynamic relocs.  */
  /* TODO: Make function to get list and not access the list directly.  */
  /* TODO: Move function to relocate_section create this relocs eagerly.  */
  /* create_got_dynrelocs_for_got_info (&h->got.glist, */
  /*                                 output_bfd, */
  /*                                 info, */
  /*                                 h); */

  /* Mark _DYNAMIC and _GLOBAL_OFFSET_TABLE_ as absolute.  */
  if (strcmp (h->root.root.string, "_DYNAMIC") == 0
      || strcmp (h->root.root.string, "__DYNAMIC") == 0
      || strcmp (h->root.root.string, "_GLOBAL_OFFSET_TABLE_") == 0)
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

static bfd_boolean
wasm32_elf_create_dynamic_sections (bfd *dynobj, struct bfd_link_info *info)
{
  bfd *abfd = dynobj;
  flagword flags, pltflags;
  register asection *s;
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);

  if (!_bfd_elf_create_dynamic_sections (dynobj, info))
    return FALSE;

  flags = (SEC_ALLOC | SEC_LOAD | SEC_HAS_CONTENTS | SEC_IN_MEMORY
           | SEC_LINKER_CREATED);

  pltflags = flags;
  pltflags |= SEC_CODE;
  if (bed->plt_not_loaded)
    pltflags &= ~ (SEC_LOAD | SEC_HAS_CONTENTS);
  if (bed->plt_readonly)
    pltflags |= SEC_READONLY;

  s = bfd_make_section_anyway_with_flags (abfd, ".wasm.payload.code.plt", pltflags);
  if (s == NULL)
    return FALSE;

  if (bed->want_plt_sym)
    {
      /* Define the symbol _PROCEDURE_LINKAGE_TABLE_ at the start of the
         .plt section.  */
      struct elf_link_hash_entry *h;
      struct bfd_link_hash_entry *bh = NULL;

      if (! (_bfd_generic_link_add_one_symbol
             (info, abfd, "_PROCEDURE_LINKAGE_TABLE_", BSF_GLOBAL, s,
              (bfd_vma) 0, (const char *) NULL, FALSE, bed->collect, &bh)))
        return FALSE;

      h = (struct elf_link_hash_entry *) bh;
      h->def_regular = 1;
      h->type = STT_OBJECT;
      elf_hash_table (info)->hplt = h;

      if (bfd_link_pic (info)
          && ! bfd_elf_link_record_dynamic_symbol (info, h))
        return FALSE;
    }

  s = bfd_make_section_anyway_with_flags (abfd, ".wasm.chars.code.plt", pltflags);
  if (s == NULL)
    return FALSE;

  if (bfd_link_executable (info))
    {
      /* Always allow copy relocs for building executables.  */
      asection *s2 = bfd_get_linker_section (dynobj, ".rela.bss");
      if (s2 == NULL)
        {
          s2 = bfd_make_section_anyway_with_flags (dynobj,
                                                  ".rela.bss",
                                                  (bed->dynamic_sec_flags
                                                   | SEC_READONLY));
          if (s2 == NULL
              || ! bfd_set_section_alignment (dynobj, s2,
                                              bed->s->log_file_align))
            return FALSE;
        }
    }

  return TRUE;
}

/* Set the sizes of the dynamic sections.  */
static bfd_boolean
elf_wasm32_size_dynamic_sections (bfd * output_bfd,
                               struct bfd_link_info *info)
{
  bfd *    dynobj;
  asection *      s;
  bfd_boolean     relocs_exist = FALSE;
  bfd_boolean     reltext_exist = FALSE;
  struct dynamic_sections ds = wasm32_create_dynamic_sections (output_bfd, info);
  struct elf_link_hash_table *htab = elf_hash_table (info);

  dynobj = (elf_hash_table (info))->dynobj;
  BFD_ASSERT (dynobj != NULL);

  if ((elf_hash_table (info))->dynamic_sections_created)
    {
      struct elf_link_hash_entry *h;

      /* Set the contents of the .interp section to the
         interpreter.  */
      if (!bfd_link_pic (info) && !info->nointerp)
        {
          s = bfd_get_section_by_name (dynobj, ".interp");
          BFD_ASSERT (s != NULL);
          s->size = sizeof (ELF_DYNAMIC_INTERPRETER);
          s->contents = (unsigned char *) strdup (ELF_DYNAMIC_INTERPRETER);
        }

      /* Add some entries to the .dynamic section.  We fill in some of
         the values later, in elf_bfd_final_link, but we must add the
         entries now so that we know the final size of the .dynamic
         section.  Checking if the .init section is present.  We also
         create DT_INIT and DT_FINI entries if the init_str has been
         changed by the user.  */
      ADD_DYNAMIC_SYMBOL (info->init_function, DT_INIT);
      ADD_DYNAMIC_SYMBOL (info->fini_function, DT_FINI);
    }
  else
    {
      /* We may have created entries in the .rela.got section.
         However, if we are not creating the dynamic sections, we will
         not actually use these entries.  Reset the size of .rela.got,
         which will cause it to get stripped from the output file
         below.  */
      if (htab->srelgot != NULL)
        htab->srelgot->size = 0;
    }

  if (htab->splt != NULL && htab->splt->size == 0)
    htab->splt->flags |= SEC_EXCLUDE;
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
        continue;

      if (strncmp (s->name, ".rela", 5) == 0)
        {
          if (s->size == 0)
            {
              s->flags |= SEC_EXCLUDE;
            }
          else
            {
              if (strcmp (s->name, ".rela.plt") != 0)
                {
                  const char *outname =
                    bfd_get_section_name (output_bfd,
                                          htab->srelplt->output_section);

                  asection *target = bfd_get_section_by_name (output_bfd,
                                                              outname + 4);

                  relocs_exist = TRUE;
                  if (target != NULL && target->size != 0
                      && (target->flags & SEC_READONLY) != 0
                      && (target->flags & SEC_ALLOC) != 0)
                    reltext_exist = TRUE;
                }
            }

          /* We use the reloc_count field as a counter if we need to
             copy relocs into the output file.  */
          s->reloc_count = 0;
        }

      if (strcmp (s->name, ".dynamic") == 0)
        continue;

      if (s->size != 0)
        s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);

      if (s->contents == NULL && s->size != 0)
        return FALSE;
    }

  if (ds.sdyn)
    {
      /* TODO: Check if this is needed.  */
      if (!bfd_link_pic (info))
        if (!_bfd_elf_add_dynamic_entry (info, DT_DEBUG, 0))
                return FALSE;

      if (htab->splt && (htab->splt->flags & SEC_EXCLUDE) == 0)
        if (!_bfd_elf_add_dynamic_entry (info, DT_PLTGOT, 0)
            || !_bfd_elf_add_dynamic_entry (info, DT_PLTRELSZ, 0)
            || !_bfd_elf_add_dynamic_entry (info, DT_PLTREL, DT_RELA)
            || !_bfd_elf_add_dynamic_entry (info, DT_JMPREL, 0)
           )
          return FALSE;

      if (relocs_exist == TRUE)
        if (!_bfd_elf_add_dynamic_entry (info, DT_RELA, 0)
            || !_bfd_elf_add_dynamic_entry (info, DT_RELASZ, 0)
            || !_bfd_elf_add_dynamic_entry (info, DT_RELAENT,
                                            sizeof (Elf32_External_Rela))
           )
          return FALSE;

      if (reltext_exist == TRUE)
        if (!_bfd_elf_add_dynamic_entry (info, DT_TEXTREL, 0))
          return FALSE;
    }

  return TRUE;
}

static bfd_boolean
elf_wasm32_finish_dynamic_sections (bfd * output_bfd,
                                 struct bfd_link_info *info)
{
  struct dynamic_sections ds = wasm32_create_dynamic_sections (output_bfd, info);
  struct elf_link_hash_table *htab = elf_hash_table (info);
  bfd *dynobj = (elf_hash_table (info))->dynobj;

  if (ds.sdyn)
    {
      Elf32_External_Dyn *dyncon, *dynconend;

      dyncon = (Elf32_External_Dyn *) ds.sdyn->contents;
      dynconend
        = (Elf32_External_Dyn *) (ds.sdyn->contents + ds.sdyn->size);
      for (; dyncon < dynconend; dyncon++)
        {
          Elf_Internal_Dyn internal_dyn;
          bfd_boolean     do_it = FALSE;

          struct elf_link_hash_entry *h = NULL;
          asection       *s = NULL;

          bfd_elf32_swap_dyn_in (dynobj, dyncon, &internal_dyn);

          switch (internal_dyn.d_tag)
            {
              GET_SYMBOL_OR_SECTION (DT_INIT, info->init_function, NULL)
              GET_SYMBOL_OR_SECTION (DT_FINI, info->fini_function, NULL)
              GET_SYMBOL_OR_SECTION (DT_PLTGOT, NULL, ".wasm.payload.code.plt")
              GET_SYMBOL_OR_SECTION (DT_JMPREL, NULL, ".rela.plt")
              GET_SYMBOL_OR_SECTION (DT_PLTRELSZ, NULL, ".rela.plt")
              GET_SYMBOL_OR_SECTION (DT_VERSYM, NULL, ".gnu.version")
              GET_SYMBOL_OR_SECTION (DT_VERDEF, NULL, ".gnu.version_d")
              GET_SYMBOL_OR_SECTION (DT_VERNEED, NULL, ".gnu.version_r")
              default:
                break;
            }

          /* In case the dynamic symbols should be updated with a symbol.  */
          if (h != NULL
              && (h->root.type == bfd_link_hash_defined
                  || h->root.type == bfd_link_hash_defweak))
            {
              asection       *asec_ptr;

              internal_dyn.d_un.d_val = h->root.u.def.value;
              asec_ptr = h->root.u.def.section;
              if (asec_ptr->output_section != NULL)
                {
                  internal_dyn.d_un.d_val +=
                    (asec_ptr->output_section->vma
                     + asec_ptr->output_offset);
                }
              else
                {
                  /* The symbol is imported from another shared
                     library and does not apply to this one.  */
                  internal_dyn.d_un.d_val = 0;
                }
              do_it = TRUE;
            }
          else if (s != NULL) /* With a section information.  */
            {
              switch (internal_dyn.d_tag)
                {
                  case DT_PLTGOT:
                  case DT_JMPREL:
                  case DT_VERSYM:
                  case DT_VERDEF:
                  case DT_VERNEED:
                    internal_dyn.d_un.d_ptr = (s->output_section->vma
                                               + s->output_offset);
                    do_it = TRUE;
                    break;

                  case DT_PLTRELSZ:
                    internal_dyn.d_un.d_val = s->size;
                    do_it = TRUE;
                    break;

                  default:
                    break;
                }
            }

          if (do_it)
            bfd_elf32_swap_dyn_out (output_bfd, &internal_dyn, dyncon);
        }

      if (htab->splt->size > 0)
        {
          //relocate_plt_for_entry (output_bfd, info);
        }

      /* TODO: Validate this.  */
      elf_section_data (htab->srelplt->output_section)->this_hdr.sh_entsize
        = 0xc;
    }

  return TRUE;
}

static bfd_reloc_status_type
wasm32_relocate_contents (reloc_howto_type *howto,
                        bfd *input_bfd,
                        bfd_vma relocation,
                          bfd_byte *location);

static bfd_reloc_status_type
wasm32_final_link_relocate (reloc_howto_type *howto,
                          bfd *input_bfd,
                          asection *input_section,
                          bfd_byte *contents,
                          bfd_vma address,
                          bfd_vma value,
                          bfd_vma addend)
{
  bfd_vma relocation;

  /* This function assumes that we are dealing with a basic relocation
     against a symbol.  We want to compute the value of the symbol to
     relocate to.  This is just VALUE, the value of the symbol, plus
     ADDEND, any addend associated with the reloc.  */
  relocation = value + addend;

  /* If the relocation is PC relative, we want to set RELOCATION to
     the distance between the symbol (currently in RELOCATION) and the
     location we are relocating.  Some targets (e.g., i386-aout)
     arrange for the contents of the section to be the negative of the
     offset of the location within the section; for such targets
     pcrel_offset is FALSE.  Other targets (e.g., m88kbcs or ELF)
     simply leave the contents of the section as zero; for such
     targets pcrel_offset is TRUE.  If pcrel_offset is FALSE we do not
     need to subtract out the offset of the location within the
     section (which is just ADDRESS).  */
  if (howto->pc_relative)
    {
      relocation -= (input_section->output_section->vma
                     + input_section->output_offset);
      if (howto->pcrel_offset)
        relocation -= address;
    }

  return wasm32_relocate_contents (howto, input_bfd, relocation,
                                 contents
                                 + address * bfd_octets_per_byte (input_bfd));
}

/* Relocate a given location using a given value and howto.  */

static bfd_reloc_status_type
wasm32_relocate_contents (reloc_howto_type *howto,
                        bfd *input_bfd,
                        bfd_vma relocation,
                        bfd_byte *location)
{
  int size;
  bfd_vma x = 0;
  bfd_reloc_status_type flag = bfd_reloc_ok;
  unsigned int rightshift = howto->rightshift;
  unsigned int bitpos = howto->bitpos;

  if (howto->special_function == wasm32_elf32_leb128_reloc)
    {
      unsigned long long value = 0;

      int len = 0;
      int i;
      int shift = 0;
      uint8_t c = 0;
      while ((c = bfd_get_8 (input_bfd, location + len++)) & 0x80)
        {
          if (shift < 63)
            value += (c&0x7f)<<shift;
          shift += 7;
        }
      if (shift < 63)
        value += (c&0x7f)<<shift;

      value += relocation;

      for (i = 0; i < len-1; i++)
        {
          bfd_put_8 (input_bfd, 0x80 | (value & 0x7f), location + i);
          value >>= 7;
        }
      bfd_put_8 (input_bfd, (value & 0x7f), location + i);

      return flag;
    }
  else if (howto->special_function == wasm32_elf32_hex16_reloc)
    {
      unsigned long long value = 0;
      char out[17];
      int i;

      for (i = 0; i < 16; i++)
        out[i] = bfd_get_8 (input_bfd, location + i);
      out[16] = 0;

      sscanf(out, "%llx", &value);
      value += relocation;

      for (i = 0; i < 16; i++)
        out[i] = ' ';
      out[16] = 0;

      sprintf(out, "%llx", value);

      for (i = 0; i < 16; i++)
        {
          bfd_put_8 (input_bfd, out[i] ? out[i] : ' ', location + i);
        }

      return flag;
    }

  /* If the size is negative, negate RELOCATION.  This isn't very
     general.  */
  if (howto->size < 0)
    relocation = -relocation;

  /* Get the value we are going to relocate.  */
  size = bfd_get_reloc_size (howto);
  switch (size)
    {
    default:
      abort ();
    case 0:
      return bfd_reloc_ok;
    case 1:
      x = bfd_get_8 (input_bfd, location);
      break;
    case 2:
      x = bfd_get_16 (input_bfd, location);
      break;
    case 4:
      x = bfd_get_32 (input_bfd, location);
      break;
    case 8:
#ifdef BFD64
      x = bfd_get_64 (input_bfd, location);
#else
      abort ();
#endif
      break;
    }

  /* Check for overflow.  FIXME: We may drop bits during the addition
     which we don't check for.  We must either check at every single
     operation, which would be tedious, or we must do the computations
     in a type larger than bfd_vma, which would be inefficient.  */
  flag = bfd_reloc_ok;

  /* Put RELOCATION in the right bits.  */
  relocation >>= (bfd_vma) rightshift;
  relocation <<= (bfd_vma) bitpos;

  /* Add RELOCATION to the right bits of X.  */
  x = ((x & ~howto->dst_mask)
       | (((x & howto->src_mask) + relocation) & howto->dst_mask));

  /* Put the relocated value back in the object file.  */
  switch (size)
    {
    default:
      abort ();
    case 1:
      bfd_put_8 (input_bfd, x, location);
      break;
    case 2:
      bfd_put_16 (input_bfd, x, location);
      break;
    case 4:
      bfd_put_32 (input_bfd, x, location);
      break;
    case 8:
#ifdef BFD64
      bfd_put_64 (input_bfd, x, location);
#else
      abort ();
#endif
      break;
    }

  return flag;
}

static bfd_boolean
wasm32_elf32_relocate_section (bfd *output_bfd ATTRIBUTE_UNUSED,
                           struct bfd_link_info *info, bfd *input_bfd,
                           asection *input_section, bfd_byte *contents,
                           Elf_Internal_Rela *relocs,
                           Elf_Internal_Sym *local_syms,
                           asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel, *relend;
  bfd_vma *local_got_offsets;
  asection *sgot;
  asection *splt;
  //asection *splt;
  asection *sreloc;

  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (input_bfd);
  local_got_offsets = elf_local_got_offsets (input_bfd);

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      int r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym;
      asection *sec;
      struct elf_link_hash_entry *h;
      bfd_vma relocation;
      bfd_vma addend = (bfd_vma)0;
      bfd_reloc_status_type r;

      r_symndx = ELF32_R_SYM (rel->r_info);

      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_type == (int) R_ASMJS_NONE)
        continue;

      howto = wasm32_elf32_howto_table + r_type;

      h = NULL;
      sym = NULL;
      sec = NULL;
      relocation = 0;
      if (r_symndx < symtab_hdr->sh_info) /* Local symbol. */
        {
          sym = local_syms + r_symndx;
          sec = local_sections[r_symndx];
          relocation = sec->output_section->vma
            + sec->output_offset
            + sym->st_value;

          if (sec != NULL && discarded_section (sec))
            /* Handled below.  */
            ;
          else if (bfd_link_relocatable (info))
            {
              /* This is a relocatable link.  We don't have to change
                 anything, unless the reloc is against a section symbol,
                 in which case we have to adjust according to where the
                 section symbol winds up in the output section.  */
              if (ELF_ST_TYPE (sym->st_info) == STT_SECTION)
                goto final_link_relocate;

              continue;
            }
          else if (! howto->partial_inplace)
            {
              relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
            }
        }
      else /* Global symbol. */
        {
          if (sym_hashes == NULL)
            return FALSE;

          h = sym_hashes[r_symndx - symtab_hdr->sh_info];
          while (h->root.type == bfd_link_hash_indirect
                 || h->root.type == bfd_link_hash_warning)
            {
              h = (struct elf_link_hash_entry *) h->root.u.i.link;
            }

          if (h->root.type == bfd_link_hash_defined
              || h->root.type == bfd_link_hash_defweak)
            {
              sec = h->root.u.def.section;
              /* The cases above are those in which relocation is
                     overwritten in the switch block below.  The cases
                     below are those in which we must defer relocation
                     to run-time, because we can't resolve absolute
                     addresses when creating a shared library.  */
              if ((sec->output_section == NULL
                      && ((input_section->flags & SEC_DEBUGGING) != 0
                          && h->def_dynamic)))
                ;
              else if (sec->output_section != NULL)
                relocation = ((h->root.u.def.value
                               + sec->output_section->vma
                               + sec->output_offset));
              else if (!bfd_link_relocatable (info)
                       && (_bfd_elf_section_offset (output_bfd, info,
                                                    input_section,
                                                    rel->r_offset)
                           != (bfd_vma) -1))
                {
                  _bfd_error_handler
                    /* xgettext:c-format */
                    (_("%B(%A+0x%lx): unresolvable %s relocation against symbol `%s'"),
                     input_bfd,
                     input_section,
                     (long) rel->r_offset,
                     howto->name,
                     h->root.root.string);
                }
            }
          else if (h->root.type == bfd_link_hash_undefweak)
            ;
          else if (info->unresolved_syms_in_objects == RM_IGNORE
                   && ELF_ST_VISIBILITY (h->other) == STV_DEFAULT)
            ;
          else if (!bfd_link_relocatable (info))
            (*info->callbacks->undefined_symbol)
              (info, h->root.root.string, input_bfd,
               input_section, rel->r_offset,
               (info->unresolved_syms_in_objects == RM_GENERATE_ERROR
                || ELF_ST_VISIBILITY (h->other)));
        }
      if (sec != NULL && discarded_section (sec))
        {
          continue; /* XXX */
          RELOC_AGAINST_DISCARDED_SECTION (info, input_bfd, input_section,
                                         rel, 1, relend, howto, 0, contents);
        }

      if (bfd_link_relocatable (info))
        continue;

      switch ((int)r_type)
        {
        case R_ASMJS_LEB128_PLT:
          /* Relocation is to the entry for this symbol in the
             procedure linkage table.  */

          /* Resolve a PLT reloc against a local symbol directly,
             without using the procedure linkage table.  */
          if (h == NULL)
            goto final_link_relocate;

          if (ELF_ST_VISIBILITY (h->other) == STV_INTERNAL
              || ELF_ST_VISIBILITY (h->other) == STV_HIDDEN)
            goto final_link_relocate;

          if (h->plt.offset == (bfd_vma) -1)
            {
              /* We didn't make a PLT entry for this symbol.  This
                 happens when statically linking PIC code, or when
                 using -Bsymbolic.  */
              goto final_link_relocate;
            }

          splt = elf_hash_table (info)->splt;
          BFD_ASSERT (splt != NULL);

          struct elf_link_hash_entry *h2;
          h2 = elf_link_hash_lookup (elf_hash_table (info),
                                     ".wasm.plt_bias", FALSE, FALSE, TRUE);
          BFD_ASSERT (h2 != NULL);

          relocation = h->plt.offset/0x40 + h2->root.u.def.value;
          addend = rel->r_addend;

          goto final_link_relocate;

        case R_ASMJS_LEB128_GOT:
          /* Relocation is to the entry for this symbol in the global
             offset table.  */
          sgot = elf_hash_table (info)->sgot;
          BFD_ASSERT (sgot != NULL);

          if (h != NULL)
            {
              bfd_vma off;

              off = h->got.offset;
              if (off == (bfd_vma) -1)
                {
                  fprintf(stderr, "that should have happened earlier\n");
                  off = h->got.offset = sgot->size;

                  if (h->dynindx == -1)
                    if (! bfd_elf_link_record_dynamic_symbol (info, h))
                      return FALSE;

                  //srelgot->size += sizeof (Elf32_External_Rela);
                }
              BFD_ASSERT (off != (bfd_vma) -1);

              relocation = sgot->output_offset/*XXX*/ + off;
            }
          else
            {
              bfd_vma off;

              if (rel->r_addend)
                {
                  BFD_ASSERT (local_got_offsets != NULL
                              && (local_got_offsets[r_symndx]
                                  != (bfd_vma) -1));

                  off = local_got_offsets[r_symndx];

                  relocation += rel->r_addend;
                }
              else
                {
                  BFD_ASSERT (local_got_offsets != NULL
                              && local_got_offsets[r_symndx] != (bfd_vma) -1);

                  off = local_got_offsets[r_symndx];
                }

              off &= ~1LL;
              if (off & 1)
                off &= ~1LL;
              else
                {
                  bfd_put_32 (output_bfd, relocation, sgot->contents + off);

                  if (bfd_link_pic (info)) {
                    asection *s;
                    Elf_Internal_Rela outrel;
                    bfd_byte *loc;

                    s = elf_hash_table (info)->srelgot;
                    BFD_ASSERT (s != NULL);

                    outrel.r_offset = (sgot->output_section->vma
                                       + sgot->output_offset
                                       + off);
                    outrel.r_info = ELF32_R_INFO (0, R_ASMJS_REL32);
                    outrel.r_addend = relocation;
                    loc = s->contents;
                    loc += s->reloc_count++ * sizeof (Elf32_External_Rela);
                    bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);

                  }
                  local_got_offsets[r_symndx] |= 1;
                  relocation = sgot->output_offset + off;
                }
            }

          relocation += 0x40;
          goto final_link_relocate;

        case R_ASMJS_ABS32:
          if (bfd_link_pic (info)
	      && (h == NULL
		  || ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
		  || h->root.type != bfd_link_hash_undefweak)
	      && r_symndx != STN_UNDEF
	      && (input_section->flags & SEC_ALLOC) != 0)
	    {
	      Elf_Internal_Rela outrel;
	      bfd_byte *loc;
	      bfd_boolean skip, relocate;

	      /* When generating a shared object, these relocations
		 are copied into the output file to be resolved at run
		 time.  */

	      if (sreloc == NULL)
		{
		  sreloc = _bfd_elf_get_dynamic_reloc_section
		    (input_bfd, input_section, /*rela?*/ TRUE);
		  if (sreloc == NULL)
		    return FALSE;
		}

	      skip = FALSE;
	      relocate = FALSE;

	      outrel.r_offset =
		_bfd_elf_section_offset (output_bfd, info, input_section,
					 rel->r_offset);
	      if (outrel.r_offset == (bfd_vma) -1)
		skip = TRUE;
	      else if (outrel.r_offset == (bfd_vma) -2)
		skip = TRUE, relocate = TRUE;
	      outrel.r_offset += (input_section->output_section->vma
				  + input_section->output_offset);

	      if (skip)
		memset (&outrel, 0, sizeof outrel);
	      else
		{
		  /* h->dynindx may be -1 if this symbol was marked to
		     become local.  */
		  if (h == NULL
		      || ((info->symbolic || h->dynindx == -1)
			  && h->def_regular))
		    {
		      relocate = howto->partial_inplace;
		      outrel.r_info = ELF32_R_INFO (0, R_ASMJS_ABS32);
		    }
		  else
		    {
		      BFD_ASSERT (h->dynindx != -1);
		      outrel.r_info = ELF32_R_INFO (h->dynindx, R_ASMJS_ABS32);
		    }
		  outrel.r_addend = relocation;
		  outrel.r_addend
		    += (howto->partial_inplace
			? bfd_get_32 (input_bfd, contents + rel->r_offset)
			: addend);
		}

	      loc = sreloc->contents;
	      loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
	      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);

	      /* If this reloc is against an external symbol, we do
		 not want to fiddle with the addend.  Otherwise, we
		 need to include the symbol value so that it becomes
		 an addend for the dynamic reloc.  */
	      if (! relocate)
		continue;
	    }
        case R_ASMJS_LEB128:
        case R_ASMJS_HEX16:
        case R_ASMJS_REL32:
          addend = rel->r_addend;
          /* Fall through.  */
        final_link_relocate:
          r = wasm32_final_link_relocate (howto, input_bfd, input_section,
                                          contents, rel->r_offset,
                                          relocation, addend);
          break;

        default:
          fprintf (stderr, "unknown reloc type %d\n", r_type);
          bfd_set_error (bfd_error_bad_value);
          return FALSE;

        }

      if (r != bfd_reloc_ok)
        {
          switch (r)
            {
            default:
            case bfd_reloc_outofrange:
              abort ();
            case bfd_reloc_overflow:
              {
                const char *name;

                if (h != NULL)
                  name = NULL;
                else
                  {
                    name = (bfd_elf_string_from_elf_section
                            (input_bfd, symtab_hdr->sh_link, sym->st_name));
                    if (name == NULL)
                      return FALSE;
                    if (*name == '\0')
                      name = bfd_section_name (input_bfd, sec);
                  }
                (*info->callbacks->reloc_overflow)
                  (info, (h ? &h->root : NULL), name, howto->name,
                   (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
              }
              break;
            }
        }
    }
  return TRUE;
}

#define elf_backend_relocate_section	wasm32_elf32_relocate_section
#define elf_backend_check_relocs elf_wasm32_check_relocs
#define elf_backend_adjust_dynamic_symbol    elf_wasm32_adjust_dynamic_symbol
#define elf_backend_finish_dynamic_symbol    elf_wasm32_finish_dynamic_symbol
#define elf_backend_create_dynamic_sections wasm32_elf_create_dynamic_sections
#define elf_backend_finish_dynamic_sections  elf_wasm32_finish_dynamic_sections
#define elf_backend_size_dynamic_sections    elf_wasm32_size_dynamic_sections
#define elf_backend_want_got_plt 1
#define elf_backend_plt_readonly 1
#define elf_backend_got_header_size 12

#include "elf32-target.h"
