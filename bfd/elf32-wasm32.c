/* 32-bit ELF for the WebAssembly target
   Copyright (C) 2017-2020 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

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
#include "libiberty.h"
#include "elf/wasm32.h"
#include <unistd.h>

static bfd_reloc_status_type
elf32_wasm32_leb128_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                           arelent *reloc_entry,
                           asymbol *symbol,
                           void *data ATTRIBUTE_UNUSED,
                           asection *input_section,
                           bfd *output_bfd,
                           char **error_message ATTRIBUTE_UNUSED);

static reloc_howto_type elf32_wasm32_howto_table[] =
{
  /* BFD_NONE relocation.  Used for debug relocs into discarded sections.  */
  HOWTO (R_WASM32_NONE,		/* type */
	 0,			/* rightshift */
	 3,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WASM32_NONE",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* 32-bit absolute relocation.  */
  HOWTO (R_WASM32_32,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_WASM32_32",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* 32-bit relative relocation.  */
  HOWTO (R_WASM32_REL32,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         TRUE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_REL32",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffff,		/* src_mask */
         0xffffffff,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* Standard LEB-128 relocation.  */
  HOWTO (R_WASM32_LEB128,	/* type */
         0,			/* rightshift */
         7,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         elf32_wasm32_leb128_reloc,/* special_function */
         "R_WASM32_LEB128",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* LEB-128 GOT offset.  */
  HOWTO (R_WASM32_LEB128_GOT,	/* type */
         0,			/* rightshift */
         7,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         elf32_wasm32_leb128_reloc,/* special_function */
         "R_WASM32_LEB128_GOT",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* LEB-128 PLT index.  As a special case, this is replaced with five
     0x00 bytes for undefined weak symbols.  */
  HOWTO (R_WASM32_LEB128_PLT,	/* type */
         0,			/* rightshift */
         7,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         elf32_wasm32_leb128_reloc,/* special_function */
         "R_WASM32_LEB128_PLT",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* PLT index.  */
  HOWTO (R_WASM32_PLT_INDEX,     /* type */
         0,			/* rightshift */
         7,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         elf32_wasm32_leb128_reloc,/* special_function */
         "R_WASM32_PLT_INDEX",   /* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* 32-bit absolute relocation for code.  */
  HOWTO (R_WASM32_32_CODE,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_32_CODE",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffff,		/* src_mask */
         0xffffffff,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* Copy relocation.  */
  HOWTO (R_WASM32_COPY,		/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_COPY",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffff,		/* src_mask */
         0xffffffff,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* LEB-128 relocation for code references.  */
  HOWTO (R_WASM32_LEB128_GOT_CODE, /* type */
         0,			/* rightshift */
         7,			/* size - 16 bytes*/
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed,/* complain_on_overflow */
         elf32_wasm32_leb128_reloc,/* special_function */
         "R_WASM32_LEB128_GOT_CODE",/* name */
         FALSE,			/* partial_inplace */
         0xffffffffffffffff,	/* src_mask */
         0xffffffffffffffff,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* Dummy relocation to pull in code.  */
  HOWTO (R_WASM32_CODE_POINTER,	/* type */
         0,			/* rightshift */
         0,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_CODE_POINTER",/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0,			/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* Dummy relocation to pull in function types.  */
  HOWTO (R_WASM32_INDEX,        /* type */
         0,			/* rightshift */
         0,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_INDEX",       /* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0,			/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* Dummy relocation to specify PLT signature.  */
  HOWTO (R_WASM32_PLT_SIG,      /* type */
         0,			/* rightshift */
         0,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_PLT_SIG",       /* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0,			/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* 32-bit relative relocation.  */
  HOWTO (R_WASM32_REL32_CODE,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         TRUE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_REL32_CODE",	/* name */
         FALSE,			/* partial_inplace */
         0xffffffff,		/* src_mask */
         0xffffffff,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* Dummy relocation to specify PLT laziness.  */
  HOWTO (R_WASM32_PLT_LAZY,     /* type */
         0,			/* rightshift */
         0,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_WASM32_PLT_LAZY",       /* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0,			/* dst_mask */
         FALSE),		/* pcrel_offset */
};

/* Look up the relocation R_NAME.  */

static reloc_howto_type *
elf32_wasm32_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				const char *r_name)
{
  unsigned int i;

  for (i = 0; i < ARRAY_SIZE (elf32_wasm32_howto_table); i++)
    if (elf32_wasm32_howto_table[i].name != NULL
	&& strcasecmp (elf32_wasm32_howto_table[i].name, r_name) == 0)
      return &elf32_wasm32_howto_table[i];

  return NULL;
};

/* Look up the relocation CODE.  */

static reloc_howto_type *
elf32_wasm32_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                enum bfd_reloc_code_real code)
{
  switch (code) {
  case BFD_RELOC_32:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_32");
  case BFD_RELOC_32_PCREL:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_REL32");
  case BFD_RELOC_WASM32_REL32_CODE:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_REL32_CODE");
  case BFD_RELOC_WASM32_LEB128:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_LEB128");
  case BFD_RELOC_WASM32_LEB128_GOT:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_LEB128_GOT");
  case BFD_RELOC_WASM32_LEB128_GOT_CODE:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_LEB128_GOT_CODE");
  case BFD_RELOC_WASM32_LEB128_PLT:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_LEB128_PLT");
  case BFD_RELOC_WASM32_PLT_INDEX:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_PLT_INDEX");
  case BFD_RELOC_WASM32_PLT_LAZY:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_PLT_LAZY");
  case BFD_RELOC_WASM32_PLT_SIG:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_PLT_SIG");
  case BFD_RELOC_WASM32_COPY:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_COPY");
  case BFD_RELOC_WASM32_CODE_POINTER:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_CODE_POINTER");
  case BFD_RELOC_WASM32_INDEX:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_INDEX");
  case BFD_RELOC_NONE:
    return elf32_wasm32_reloc_name_lookup(abfd, "R_WASM32_NONE");
  default:
    return NULL;
  }
}

/* Look up the relocation R_TYPE.  */

static reloc_howto_type *
elf32_wasm32_rtype_to_howto (bfd *abfd, unsigned r_type)
{
  unsigned int i = r_type;

  if (i >= ARRAY_SIZE (elf32_wasm32_howto_table))
    {
      /* xgettext:c-format */
      _bfd_error_handler (_("%pB: unsupported relocation type %#x"),
			  abfd, r_type);
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }

  if (elf32_wasm32_howto_table[i].type != r_type)
    return NULL;

  return elf32_wasm32_howto_table + i;
}

/* Translate the ELF-internal relocation RELA into CACHE_PTR.  */

static bfd_boolean
elf32_wasm32_info_to_howto_rela (bfd *abfd ATTRIBUTE_UNUSED,
                                 arelent *cache_ptr,
                                 Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE (dst->r_info);

  cache_ptr->howto = elf32_wasm32_rtype_to_howto (abfd, r_type);
  return cache_ptr->howto != NULL;
}

/* Whether to generate a "name" section entry for PLT stubs.  Should
   be a user option.  */
#define PLTNAME 1

#define TARGET_LITTLE_SYM	wasm32_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-wasm32"

#define ADD_DYNAMIC_SYMBOL(NAME, TAG)					\
  h =  elf_link_hash_lookup (elf_hash_table (info),			\
                             NAME, FALSE, FALSE, FALSE);		\
  if ((h != NULL && (h->ref_regular || h->def_regular)))		\
    if (! _bfd_elf_add_dynamic_entry (info, TAG, 0))			\
      return FALSE;

#define elf_backend_can_gc_sections	1
#define elf_backend_rela_normal		1
/* For testing. */
#define elf_backend_want_dynrelro	1

#define GET_SYMBOL_OR_SECTION(TAG, SYMBOL, SECTION)		\
  case TAG:							\
  if (SYMBOL != NULL)						\
    h = elf_link_hash_lookup (elf_hash_table (info),		\
                              SYMBOL, FALSE, FALSE, TRUE);	\
  else if (SECTION != NULL)					\
    s = bfd_get_linker_section (dynobj, SECTION);		\
  break;

/* Store VALUE at ADDR in ABFD's address space, using an LEB128
   encoding of the same length as already exists at ADDR.  Do not
   write past END.  */

#define ELF_DYNAMIC_INTERPRETER	 "/sbin/elf-dynamic-interpreter.so"

static inline bfd_boolean
set_uleb128 (bfd *abfd ATTRIBUTE_UNUSED,
             unsigned long long value,
             bfd_byte *addr, bfd_byte *end)
{
  int len = 0;
  int i;


  while (bfd_get_8 (abfd, addr + len++) & 0x80)
    {
      if (addr + len >= end)
        return FALSE;
    }

  for (i = 0; i < len-1; i++)
    {
      bfd_put_8 (abfd, 0x80 | (value & 0x7f), addr + i);
      value >>= 7;
    }
  bfd_put_8 (abfd, (value & 0x7f), addr + i);
  value >>= 7;

  return (value == 0);
}

static bfd_reloc_status_type
elf32_wasm32_leb128_reloc (bfd *abfd ATTRIBUTE_UNUSED,
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
  octets = reloc_entry->address * bfd_octets_per_byte (abfd, symbol->section);

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

  if (flag == bfd_reloc_ok
      && ! set_uleb128 (abfd, relocation, data + octets, data
                        + bfd_get_section_limit (abfd, input_section)))
    flag = bfd_reloc_overflow;

  return flag;
}

reloc_howto_type *
elf32_wasm32_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                              const char *r_name);


reloc_howto_type *
elf32_wasm32_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                              enum bfd_reloc_code_real code);


reloc_howto_type *
elf32_wasm32_info_to_howto_ptr (unsigned int r_type);

reloc_howto_type *
elf32_wasm32_info_to_howto_ptr (unsigned int r_type)
{
  if (r_type > R_WASM32_max)
    r_type = 0;

  return &elf32_wasm32_howto_table[r_type];
}

void
elf32_wasm32_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
                              Elf_Internal_Rela *dst);
void
elf32_wasm32_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
                              Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE (dst->r_info);

  cache_ptr->howto = elf32_wasm32_info_to_howto_ptr (r_type);
}

struct elf32_wasm32_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* The symbol defining our PLT signature.  */
  struct elf_link_hash_entry *pltsig;

  /* Index into .space.code_.plt.  */
  bfd_vma plt_index;
  /* Index into .space.name.function_.plt.  */
  bfd_vma pltnameoff;
  /* Index into .space.function_.plt.  */
  bfd_vma pltfunction;
  /* Pointer to PLT stub.  */
  bfd_byte *pltstub;
  /* Size of PLT stub.  */
  bfd_vma pltstub_size;
  /* Offset of the PLT index in the PLT stub.  */
  bfd_vma pltstub_pltoff;
  /* Offset of the signature index in the PLT stub.  */
  bfd_vma pltstub_sigoff;
};

#define elf32_wasm32_hash_entry(ent) ((struct elf32_wasm32_link_hash_entry *)(ent))

struct dynamic_sections
{
  bfd_boolean initialized;
  asection *  sgot;            /* .got */
  asection *  srelgot;         /* .rela.got */
  asection *  sdyn;            /* .dynamic */
  asection *  sdynbss;         /* .dynbss */
  asection *  srelbss;         /* .rela.bss */

  asection *  splt;            /* .wasm.code_.plt */
  asection *  spltspace;       /* .space.code_.plt */
  asection *  spltfun;         /* .wasm.function_.plt */
  asection *  spltfunspace;    /* .space.function_.plt */
  asection *  spltidx;         /* .space.function_index_.plt */
  asection *  srelplt;         /* .rela.plt */
  asection *  spltelem;        /* .wasm.element_.plt */
  asection *  spltelemspace;   /* .space.element_.plt */
  asection *  spltname;        /* .wasm.name.function_.plt */
  asection *  spltnamespace;   /* .space.name.function_.plt */
};

#define elf32_wasm32_hash_table(info) ((struct elf32_wasm32_link_hash_table *)elf_hash_table (info))

/* WASM32 ELF linker hash table.  */
struct elf32_wasm32_link_hash_table
{
  struct elf_link_hash_table root;
  struct dynamic_sections ds;
};

/* Create a wasm32 ELF linker hash table entry.  */

static struct bfd_hash_entry *
elf32_wasm32_link_hash_newfunc (struct bfd_hash_entry *entry,
                                struct bfd_hash_table *table,
                                const char *string)
{
  struct elf32_wasm32_link_hash_entry *ret =
    (struct elf32_wasm32_link_hash_entry *) entry;

  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (ret == (struct elf32_wasm32_link_hash_entry *) NULL)
    ret = ((struct elf32_wasm32_link_hash_entry *)
           bfd_hash_allocate (table,
                              sizeof (struct elf32_wasm32_link_hash_entry)));
  if (ret == (struct elf32_wasm32_link_hash_entry *) NULL)
    return (struct bfd_hash_entry *) ret;

  /* Call the allocation method of the superclass.  */
  ret = ((struct elf32_wasm32_link_hash_entry *)
         _bfd_elf_link_hash_newfunc ((struct bfd_hash_entry *) ret,
                                     table, string));
  if (ret != (struct elf32_wasm32_link_hash_entry *) NULL)
    {
      ret->plt_index = (bfd_vma) -1;
      ret->pltnameoff = (bfd_vma) -1;
      ret->pltfunction = (bfd_vma) -1;
      ret->pltstub = NULL;
      ret->pltstub_size = 0;
      ret->pltstub_pltoff = (bfd_vma) -1;
      ret->pltstub_sigoff = (bfd_vma) -1;
    }

  return (struct bfd_hash_entry *) ret;
}

/* Create a wasm32 ELF linker hash table.  */

static struct bfd_link_hash_table *
elf32_wasm32_link_hash_table_create (bfd *abfd)
{
  struct elf32_wasm32_link_hash_table *ret;
  bfd_size_type amt = sizeof (struct elf32_wasm32_link_hash_table);

  ret = (struct elf32_wasm32_link_hash_table *) bfd_zmalloc (amt);
  if (ret == (struct elf32_wasm32_link_hash_table *) NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&ret->root, abfd,
                                      elf32_wasm32_link_hash_newfunc,
                                      sizeof (struct elf32_wasm32_link_hash_entry),
                                      WASM_ELF_DATA))
    {
      free (ret);
      return NULL;
    }

  return &ret->root.root;
}

/* Return dynamic sections for ABFD's link INFO.  */

static struct dynamic_sections *
wasm32_create_dynamic_sections (bfd * abfd ATTRIBUTE_UNUSED,
                                struct bfd_link_info *info)
{
  struct elf_link_hash_table *htab = elf_hash_table (info);
  struct elf32_wasm32_link_hash_table *hhtab = elf32_wasm32_hash_table (info);
  struct dynamic_sections *ds = &hhtab->ds;

  if (!ds->initialized)
    {
      bfd *dynobj;

      ds->initialized = TRUE;

      dynobj = htab->dynobj;

      if (dynobj)
        {
          ds->sgot = htab->sgot;
          ds->srelgot = htab->srelgot;
          ds->spltspace = bfd_get_section_by_name
            (dynobj, ".space.code_.plt");
          ds->spltfunspace = bfd_get_section_by_name
            (dynobj, ".space.function_.plt");
          ds->spltidx = bfd_get_section_by_name
            (dynobj, ".space.function_index_.plt");
          ds->spltelemspace = bfd_get_section_by_name
            (dynobj, ".space.element_.plt");
          ds->spltnamespace = bfd_get_section_by_name
            (dynobj, ".space.name.function_.plt");

          ds->splt = bfd_get_section_by_name
            (dynobj, ".wasm.code_.plt");
          ds->spltfun = bfd_get_section_by_name
            (dynobj, ".wasm.function_.plt");
          ds->spltelem = bfd_get_section_by_name
            (dynobj, ".wasm.element_.plt");
          ds->srelplt = bfd_get_section_by_name (dynobj, ".rela.plt");
          ds->sdyn = bfd_get_section_by_name (dynobj, ".dynamic");
          ds->sdynbss = bfd_get_section_by_name (dynobj, ".dynbss");
          ds->spltname = bfd_get_section_by_name (dynobj, ".wasm.name.function_.plt");
          ds->srelbss = bfd_get_section_by_name (dynobj, ".rela.bss");
        }
      ds->initialized = TRUE;
    }

  return ds;
}

/* WebAssembly has no easy way to forward control to another function,
   so we have to build a special PLT stub for each function based on
   the number of arguments it takes, its signature index, and its PLT
   index.

   The stub code is:

       rleb128_32 1f - 0f  ; function size
0:     .byte 0             ; no locals
       local.get 0         ; if there's at least one argument
       ...
       local.get <n-1>     ; if there are at least n arguments
       global.get $plt
       i32.const <pltindex>
       i32.add
       call_indirect <pltsig> 0
       return
       end
1:

    While the code is identical for all n-argument functions, the
    function signature depends on the precise type of each argument,
    so we cannot share PLT stubs.  */

static bfd_byte *
build_plt_stub (bfd *output_bfd,
                bfd_vma signature, bfd_vma nargs, bfd_vma pltindex,
                bfd_vma *size, bfd_vma *pltstub_pltoff, bfd_vma *pltstub_sigoff)
{
  bfd_vma maxsize = 5 + 3 + nargs * 6 + 3 + 5 + 2 + 5 + 3;
  bfd_byte *ret = malloc (maxsize);
  bfd_byte *p = ret;
  bfd_vma i;

  /* Size.  Fill in later.  */
  *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0;
  *p++ = 0x00; /* No locals, just arguments.  */

  for (i = 0; i < nargs; i++)
    {
      *p++ = 0x20; /* local.get */
      *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0;
      set_uleb128 (output_bfd, i, p - 5, ret + maxsize);
    }

  *p++ = 0x23; /* global.get */
  *p++ = 0x01; /* $plt */
  *p++ = 0x41; /* i32.const */
  *pltstub_pltoff = p - ret;
  *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0;
  set_uleb128 (output_bfd, pltindex, p - 5, ret + maxsize);
  *p++ = 0x6a; /* add */
  *p++ = 0x11; /* call_indirect */
  *pltstub_sigoff = p - ret;
  *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0x80; *p++ = 0;
  set_uleb128 (output_bfd, signature, p - 5, ret + maxsize);
  *p++ = 0x00; /* Reserved argument to call_indirect.  */
  *p++ = 0x0f; /* return */
  *p++ = 0x0b; /* end */

  *size = p - ret;
  ret = realloc (ret, *size);

  set_uleb128 (output_bfd, *size - 5, ret, ret + *size);

  return ret;
}

/* Build a PLT stub for H, based on its PLT signature, and save it.
   Also, resize PLT sections.  */

static bfd_vma
add_symbol_to_plt (bfd *output_bfd, struct bfd_link_info *info,
                   struct elf_link_hash_entry *h)
{
  struct dynamic_sections *ds =
    wasm32_create_dynamic_sections (output_bfd, info);
  struct elf32_wasm32_link_hash_entry *hh = elf32_wasm32_hash_entry (h);
  struct elf_link_hash_entry *pltsig = hh->pltsig;
  bfd_vma ret;
  bfd_vma signature;
  bfd_vma nargs = 0;
  const char *p = strrchr(pltsig->root.root.string, 'F');
  struct elf_link_hash_table *htab = elf_hash_table (info);

  if (h->plt.offset != (bfd_vma) -1)
    return h->plt.offset;

  ret = ds->splt->size;
  hh->plt_index = ds->spltspace->size;

  if (!pltsig)
    abort ();

  signature = pltsig->root.u.def.section->output_offset + pltsig->root.u.def.value;
  /* We parse the name of the PLT_SIG symbol.  This is a bit of a hack.  */
  p = strrchr(pltsig->root.root.string, 'F');
  if (p)
    {
      int done = 0;

      p++;
      do
        {
          int c = *p++;

	  if (!c)
	    abort ();

          switch (c)
            {
            case 'i':
            case 'l':
            case 'f':
            case 'd':
            case 'v':
              nargs++;
              break;
            case 'E':
              done = 1;
              break;
            default:
              abort ();
            }
        }
      while (!done);
      nargs--;
    }

  hh->pltstub = build_plt_stub (output_bfd, signature, nargs,
                                hh->plt_index, &hh->pltstub_size,
                                &hh->pltstub_pltoff, &hh->pltstub_sigoff);

  ds->splt->size += hh->pltstub_size;

  htab->srelplt->size += sizeof (Elf32_External_Rela);

  ds->spltspace->size++;
  hh->pltfunction = ds->spltfun->size;
  ds->spltfun->size += 5;
  ds->spltfunspace->size++;
  ds->spltidx->size++;
  ds->spltelemspace->size++;
  ds->spltelem->size += 5;
  if (PLTNAME)
    {
      hh->pltnameoff = ds->spltname->size;
      ds->spltname->size += 5 + 5 + (h->root.root.string ? (strlen(h->root.root.string) + strlen ("@plt")) : 0);
      ds->spltnamespace->size++;
    }

  return ret;
}

static bfd_boolean
elf32_wasm32_adjust_dynamic_symbol (struct bfd_link_info *info,
                                  struct elf_link_hash_entry *h)
{
  asection *s;
  bfd *dynobj = (elf_hash_table (info))->dynobj;
  struct elf_link_hash_table *htab = elf_hash_table (info);
  asection *srel;
  struct dynamic_sections *ds = wasm32_create_dynamic_sections (dynobj, info);

  if (h->needs_plt == 1)
    {
      /* Make sure this symbol is output as a dynamic symbol.  */
      if (h->dynindx == -1 && !h->forced_local
          && !bfd_elf_link_record_dynamic_symbol (info, h))
        return FALSE;

      if (bfd_link_pic (info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL (1, 0, h))
        {
          bfd_vma loc = add_symbol_to_plt (dynobj, info, h);

          if (bfd_link_executable (info) && !h->def_regular)
            {
              struct elf32_wasm32_link_hash_entry *hh =
                elf32_wasm32_hash_entry (h);

              h->root.u.def.section = ds->spltspace;
              h->root.u.def.value = hh->plt_index;
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
  if (h->is_weakalias)
    {
      struct elf_link_hash_entry *def = weakdef (h);
      BFD_ASSERT (def->root.type == bfd_link_hash_defined);
      h->root.u.def.section = def->root.u.def.section;
      h->root.u.def.value = def->root.u.def.value;
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

  if ((h->root.u.def.section->flags & SEC_READONLY) != 0)
    {
      s = bfd_get_section_by_name (dynobj, ".data.rel.ro");
      srel = htab->sreldynrelro;
    }
  else
    {
      s = bfd_get_section_by_name (dynobj, ".dynbss");
      srel = ds->srelbss;
    }
  BFD_ASSERT (s != NULL);

  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {

      BFD_ASSERT (srel != NULL);
      srel->size += sizeof (Elf32_External_Rela);
      h->needs_copy = 1;
    }

  return _bfd_elf_adjust_dynamic_copy (info, h, s);
}

static bfd_boolean
elf32_wasm32_check_relocs (bfd *abfd, struct bfd_link_info *info, asection *sec, const Elf_Internal_Rela* relocs)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  bfd *dynobj;
  asection *sreloc = NULL;
  bfd_vma *local_got_offsets;
  asection *sgot;
  asection *srelgot;
  struct elf_link_hash_entry *pltsig = NULL;

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
      struct elf_link_hash_entry *h;
      struct elf32_wasm32_link_hash_entry *hh;
      unsigned long r_symndx = ELF32_R_SYM (rel->r_info);

      r_type = ELF32_R_TYPE (rel->r_info);

      if (dynobj == NULL
          && (r_type == R_WASM32_LEB128_PLT
              || r_type == R_WASM32_LEB128_GOT
              || r_type == R_WASM32_LEB128_GOT_CODE))
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
          if (h)
            {
              while (h->root.type == bfd_link_hash_indirect
                     || h->root.type == bfd_link_hash_warning)
                h = (struct elf_link_hash_entry *) h->root.u.i.link;

              /* PR15323, ref flags aren't set for references in the same
                 object.  */
              hh = elf32_wasm32_hash_entry (h);
            }
        }

      if (dynobj == NULL)
        switch (r_type)
          {
          case R_WASM32_LEB128_GOT:
          case R_WASM32_LEB128_GOT_CODE:
          case R_WASM32_LEB128_PLT:
            elf_hash_table (info)->dynobj = dynobj = abfd;
            if (! _bfd_elf_create_got_section (dynobj, info))
              return FALSE;
            break;
          default:
            break;
          }

      if (r_type != R_WASM32_LEB128_PLT)
        pltsig = NULL;

      switch (r_type)
        {
        case R_WASM32_LEB128_GOT:
        case R_WASM32_LEB128_GOT_CODE:
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
              h->got.offset = sgot->size + (r_type == R_WASM32_LEB128_GOT_CODE ? 2 : 0);

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
                  unsigned int i;

                  size = symtab_hdr->sh_info * sizeof (bfd_vma);
                  local_got_offsets = (bfd_vma *) bfd_alloc (abfd, size);
                  if (local_got_offsets == NULL)
                    return FALSE;
                  elf_local_got_offsets (abfd) = local_got_offsets;
                  for (i = 0; i < symtab_hdr->sh_info; i++)
                    local_got_offsets[i] = (bfd_vma) -1;
                }

              if (local_got_offsets[r_symndx] != (bfd_vma) -1)
                {
                  /* We have already allocated space in the .got.  */
                  break;
                }
              local_got_offsets[r_symndx] = sgot->size;

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


        case R_WASM32_LEB128_PLT:
          if (h)
            {
              h->needs_plt = 1;
              BFD_ASSERT (pltsig);
              hh->pltsig = pltsig;
            }
          pltsig = NULL;

          break;

        case R_WASM32_PLT_SIG:
          /* XXX this code relies on the PLT_SIG "relocation"
             appearing right before the corresponding LEB128_PLT
             relocation. That's probably not safe. */
          pltsig = h;
          break;

        case R_WASM32_LEB128:
          if (h != NULL && ! bfd_link_pic (info))
            h->non_got_ref = 1;

          break;
        case R_WASM32_32:
          if (h != NULL && bfd_link_executable (info))
            h->non_got_ref = 1;
        /* FALLTHROUGH */
        default: ;
          if (bfd_link_pic (info) &&
              r_symndx != STN_UNDEF &&
              (sec->flags & SEC_ALLOC) != 0)
            {
              if (sreloc == NULL)
                {
                  sreloc = _bfd_elf_make_dynamic_reloc_section
                    (sec, dynobj, 2, abfd, /*rela*/ TRUE);

                  if (sreloc == NULL)
                    return FALSE;
                }
              sreloc->size += sizeof (Elf32_External_Rela);
            }
        }

      if (r_type == R_WASM32_LEB128_PLT)
        {
          if (h == NULL)
            continue;
          else
            h->needs_plt = 1;
        }
    }

  return TRUE;
}

/* Actually build a PLT stub, once we've decided we need it, for
   symbol H (ELF symbol SYM).  That usually means that this is not a
   static build and H isn't local and hasn't been forced local.

   Sections affected: .wasm.code_.plt, .wasm.element_.plt,
   .wasm.function_.plt; if PLTNAME is set, also
   .wasm.name.local_.plt.  */

static void
finish_plt_entry (bfd *output_bfd, struct bfd_link_info *info,
                  struct elf_link_hash_entry *h, Elf_Internal_Sym *sym)
{
  struct elf32_wasm32_link_hash_entry *hh = (struct elf32_wasm32_link_hash_entry *)h;
  struct elf_link_hash_table *htab = elf_hash_table (info);

  if (h->plt.offset != (bfd_vma) -1)
    {
      struct dynamic_sections *ds = wasm32_create_dynamic_sections (output_bfd, info);
      asection *splt;
      asection *srel;
      asection *spltelem = ds->spltelem;
      asection *spltname = ds->spltname;

      bfd_vma plt_index;
      bfd_vma plt_bias = ds->spltidx->output_offset;
      Elf_Internal_Rela rel;
      bfd_byte *loc;

      /* This symbol has an entry in the procedure linkage table.  Set
         it up.  */

      splt = ds->splt;
      srel = htab->srelplt;
      BFD_ASSERT (splt != NULL && srel != NULL);

      /* Get the index in the procedure linkage table which
         corresponds to this symbol.  This is the index of this symbol
         in all the symbols for which we are making plt entries.  */
      plt_index = hh->plt_index;
      memcpy (splt->contents + h->plt.offset, hh->pltstub, hh->pltstub_size);

      set_uleb128 (output_bfd, plt_index + plt_bias,
                   splt->contents + h->plt.offset + hh->pltstub_pltoff,
                   splt->contents + h->plt.offset + hh->pltstub_pltoff + 5);

      for (int i = 0; i < 5; i++)
        bfd_put_8 (output_bfd,
                   (i % 5 == 4) ? 0x00 : 0x80,
                   spltelem->contents + 5 * plt_index + i);

      set_uleb128 (output_bfd, plt_index + plt_bias,
                   spltelem->contents + 5 * plt_index,
                   spltelem->contents + 5 * plt_index + 5);

      for (int i = 0; i < 5; i++)
        bfd_put_8 (output_bfd,
                   (i % 5 == 4) ? 0x00 : 0x80,
                   ds->spltfun->contents + hh->pltfunction + i);

      set_uleb128 (output_bfd,
                   hh->pltsig->root.u.def.value
                   + hh->pltsig->root.u.def.section->output_offset,
                   ds->spltfun->contents + hh->pltfunction,
                   ds->spltfun->contents + hh->pltfunction + 5);

      if (hh->pltstub_sigoff)
        set_uleb128 (output_bfd,
                     hh->pltsig->root.u.def.value
                     + hh->pltsig->root.u.def.section->output_offset,
                     splt->contents + h->plt.offset + hh->pltstub_sigoff,
                     splt->contents + h->plt.offset + hh->pltstub_sigoff + 5);

      if (PLTNAME) {
        struct elf32_wasm32_link_hash_entry *h4 = (struct elf32_wasm32_link_hash_entry *)h;

        bfd_vma index = plt_index + plt_bias;
        const char *str = h->root.root.string ? h->root.root.string : "";
        size_t len = strlen(str);
        int i;

        for (i = 0; i < 5; i++)
          bfd_put_8 (output_bfd,
                     (i % 5 == 4) ? 0x00 : 0x80,
                     spltname->contents + h4->pltnameoff + i);

        set_uleb128 (output_bfd,
                     index,
                     spltname->contents + h4->pltnameoff,
                     spltname->contents + h4->pltnameoff + 5);

        for (i = 0; i < 5; i++)
          bfd_put_8 (output_bfd,
                     (i % 5 == 4) ? 0x00 : 0x80,
                     spltname->contents + h4->pltnameoff + 5 + i);

        set_uleb128 (output_bfd,
                     len + 4,
                     spltname->contents + h4->pltnameoff + 5,
                     spltname->contents + h4->pltnameoff + 10);

        for (i = 0; str[i]; i++)
          bfd_put_8 (output_bfd,
                     str[i],
                     spltname->contents + h4->pltnameoff + 10 + i);

        if (str[0])
          {
            bfd_put_8 (output_bfd, '@', spltname->contents + h4->pltnameoff + 10 + i++);
            bfd_put_8 (output_bfd, 'p', spltname->contents + h4->pltnameoff + 10 + i++);
            bfd_put_8 (output_bfd, 'l', spltname->contents + h4->pltnameoff + 10 + i++);
            bfd_put_8 (output_bfd, 't', spltname->contents + h4->pltnameoff + 10 + i++);
          }

      }

      /* Fill in the entry in the .rela.plt section.  */
      rel.r_offset = plt_index + plt_bias;
      rel.r_info = ELF32_R_INFO (h->dynindx, R_WASM32_PLT_INDEX);
      rel.r_addend = 0;
      loc = srel->contents + plt_index * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);
      BFD_ASSERT (srel->size >= loc - srel->contents + sizeof (Elf32_External_Rela));

      if (!h->def_regular)
        {
          /* Mark the symbol as undefined, rather than as defined in
             the .plt section.  Leave the value alone.  */
          sym->st_shndx = SHN_UNDEF;
        }
    }
}

static bfd_boolean
elf32_wasm32_finish_dynamic_symbol (bfd * output_bfd,
                                    struct bfd_link_info *info,
                                    struct elf_link_hash_entry *h,
                                    Elf_Internal_Sym * sym)
{
  if (h->plt.offset != (bfd_vma) -1)
    finish_plt_entry (output_bfd, info, h, sym);

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
                      + (h->got.offset &~ 3));

      /* If this is a -Bsymbolic link, and the symbol is defined
         locally, we just want to emit a RELATIVE reloc.  Likewise if
         the symbol was forced to be local because of a version file.
         The entry in the global offset table will already have been
         initialized in the relocate_section function.  */
      if (bfd_link_pic (info)
          && (info->symbolic || h->dynindx == -1)
          && h->def_regular)
        {
          rel.r_info = ELF32_R_INFO (0, (h->got.offset & 2) ? R_WASM32_REL32_CODE : R_WASM32_REL32);
          rel.r_addend = (h->root.u.def.value
                          + h->root.u.def.section->output_section->vma
                          + h->root.u.def.section->output_offset);
        }
      else
        {
          bfd_put_32 (output_bfd, (bfd_vma) 0, sgot->contents + (h->got.offset & -4));
          rel.r_info = ELF32_R_INFO (h->dynindx, (h->got.offset & 2) ? R_WASM32_32_CODE : R_WASM32_32);
          rel.r_addend = 0;
        }

      loc = srel->contents;
      loc += srel->reloc_count++ * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);
      BFD_ASSERT (srel->size >= loc - srel->contents + sizeof (Elf32_External_Rela));
    }

  if (h->needs_copy)
    {
      asection *s;
      Elf_Internal_Rela rel;
      bfd_byte *loc;
      const char *secname = ".rela.bss";

      /* This symbol needs a copy reloc.  Set it up.  */

      BFD_ASSERT (h->dynindx != -1
                  && (h->root.type == bfd_link_hash_defined
                      || h->root.type == bfd_link_hash_defweak));

      if (strcmp(h->root.u.def.section->name, ".data.rel.ro") == 0)
        secname = ".rela.data.rel.ro";

      s = bfd_get_linker_section (elf_hash_table (info)->dynobj, secname);
      BFD_ASSERT (s != NULL);

      rel.r_offset = (h->root.u.def.value
                      + h->root.u.def.section->output_section->vma
                      + h->root.u.def.section->output_offset);
      rel.r_info = ELF32_R_INFO (h->dynindx, R_WASM32_COPY);
      rel.r_addend = 0;
      loc = s->contents + s->reloc_count++ * sizeof (Elf32_External_Rela);
      bfd_elf32_swap_reloca_out (output_bfd, &rel, loc);
      BFD_ASSERT (s->size >= loc - s->contents + sizeof (Elf32_External_Rela));
    }

  /* Mark _DYNAMIC and _GLOBAL_OFFSET_TABLE_ as absolute.  */
  if (strcmp (h->root.root.string, "_DYNAMIC") == 0
      || strcmp (h->root.root.string, "__DYNAMIC") == 0
      || strcmp (h->root.root.string, "_GLOBAL_OFFSET_TABLE_") == 0)
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

static bfd_boolean
elf32_wasm32_create_dynamic_sections (bfd *dynobj,
                                      struct bfd_link_info *info)
{
  bfd *abfd = dynobj;
  flagword flags, pltflags;
  asection *s;
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

  s = bfd_make_section_anyway_with_flags (abfd, ".space.function_.plt", pltflags & ~ (SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS));
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".space.function_index_.plt", pltflags & ~ (SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS));
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".space.function_index..text", pltflags & ~ (SEC_ALLOC | SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS));
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".space.element_.plt", pltflags & ~ (SEC_ALLOC | SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS));
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".space.name.function_.plt", pltflags & ~ (SEC_ALLOC | SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS));
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".wasm.function_.plt", pltflags & ~SEC_CODE);
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".wasm.element_.plt", pltflags & ~SEC_CODE);
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".wasm.name.function_.plt", pltflags & ~SEC_CODE);
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".space.code_.plt", pltflags & ~ (SEC_CODE | SEC_LOAD | SEC_HAS_CONTENTS));
  if (s == NULL)
    return FALSE;

  s = bfd_make_section_anyway_with_flags (abfd, ".wasm.code_.plt", pltflags);
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

  s = bfd_make_section_anyway_with_flags (abfd, ".space.code_.plt", pltflags);
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
              || ! bfd_set_section_alignment (s2, bed->s->log_file_align))
            return FALSE;
        }
    }

  return TRUE;
}


/* Allocate space in .plt, .got and associated reloc sections for
   dynamic relocs.  */

static bfd_boolean
allocate_dynrelocs (struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct elf_link_hash_table *htab;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  info = (struct bfd_link_info *) inf;
  htab = elf_hash_table (info);
  if (htab == NULL)
    return FALSE;

  if (htab->dynamic_sections_created
      && h->plt.refcount > 0
      && (ELF_ST_VISIBILITY (h->other) == STV_DEFAULT
          || h->root.type != bfd_link_hash_undefweak))
    {
      /* Make sure this symbol is output as a dynamic symbol.
         Undefined weak syms won't yet be marked as dynamic.  */
      if (h->dynindx == -1
          && !h->forced_local)
        {
          if (! bfd_elf_link_record_dynamic_symbol (info, h))
            return FALSE;
        }
    }

  /* In the shared -Bsymbolic case, discard space allocated for
     dynamic pc-relative relocs against symbols which turn out to be
     defined in regular objects.  For the normal shared case, discard
     space for pc-relative relocs that have become local due to symbol
     visibility changes.  */

  if (!bfd_link_pic (info))
    {
      /* For the non-shared case, discard space for relocs against
         symbols which turn out to need copy relocs or are not
         dynamic.  */

      if (!h->non_got_ref
          && ((h->def_dynamic
               && !h->def_regular)
              || (htab->dynamic_sections_created
                  && (h->type == bfd_link_hash_undefweak
                      || h->type == bfd_link_hash_undefined))))
        {
          /* Make sure this symbol is output as a dynamic symbol.
             Undefined weak syms won't yet be marked as dynamic.  */
          if (h->dynindx == -1
              && !h->forced_local)
            {
              if (! bfd_elf_link_record_dynamic_symbol (info, h))
                return FALSE;
            }
        }
    }

  return TRUE;
}

#define ELF_DYNAMIC_INTERPRETER  "/sbin/elf-dynamic-interpreter.so"

/* Set the sizes of the dynamic sections.  */

static bfd_boolean
elf32_wasm32_size_dynamic_sections (bfd * output_bfd,
                                    struct bfd_link_info *info)
{
  asection *s;
  bfd_boolean relocs_exist = FALSE;
  bfd_boolean reltext_exist = FALSE;
  struct dynamic_sections *ds = wasm32_create_dynamic_sections (output_bfd, info);
  struct elf_link_hash_table *htab = elf_hash_table (info);
  bfd *dynobj = htab->dynobj;

  BFD_ASSERT (dynobj != NULL);

  elf_link_hash_traverse (htab, allocate_dynrelocs, info);

  if (htab->dynamic_sections_created)
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

  if (ds->splt != NULL && ds->splt->size == 0)
    ds->splt->flags |= SEC_EXCLUDE;
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
        continue;

      if (strncmp (s->name, ".rela", 5) == 0)
        {
          if (s->size == 0)
            s->flags |= SEC_EXCLUDE;
          else
            {
              if (strcmp (s->name, ".rela.plt") != 0)
                {
                  const char *outname =
		    htab->srelplt->output_section->name;

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

      /* XXX this might still be re-allocating sections which have
         valuable data, as it used to do for .version_d.  */
      if ((s->flags & SEC_HAS_CONTENTS) && s->contents)
        continue;

      if (s->size != 0)
        s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);

      if (s->contents == NULL && s->size != 0)
        return FALSE;
    }

  if (ds->sdyn)
    {
      /* TODO: Check if this is needed.  */
      if (!bfd_link_pic (info))
        if (!_bfd_elf_add_dynamic_entry (info, DT_DEBUG, 0))
          return FALSE;

      if (ds->splt && (ds->splt->flags & SEC_EXCLUDE) == 0)
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
elf32_wasm32_finish_dynamic_sections (bfd * output_bfd,
                                      struct bfd_link_info *info)
{
  struct dynamic_sections *ds = wasm32_create_dynamic_sections (output_bfd, info);
  struct elf_link_hash_table *htab = elf_hash_table (info);
  bfd *dynobj = htab->dynobj;

  if (ds->sdyn)
    {
      Elf32_External_Dyn *dyncon, *dynconend;

      dyncon = (Elf32_External_Dyn *) ds->sdyn->contents;
      dynconend
        = (Elf32_External_Dyn *) (ds->sdyn->contents + ds->sdyn->size);
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
              GET_SYMBOL_OR_SECTION (DT_PLTGOT, NULL, ".wasm.code_.plt")
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

      /* TODO: Validate this.  */
      if (elf_section_data (htab->srelplt->output_section))
        elf_section_data (htab->srelplt->output_section)->this_hdr.sh_entsize
          = 0xc;
    }

  return TRUE;
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

  if (howto->type == R_WASM32_LEB128
      || howto->type == R_WASM32_LEB128_GOT
      || howto->type == R_WASM32_LEB128_GOT_CODE
      || howto->type == R_WASM32_LEB128_PLT)
    {
      int len = 0;
      int i;
      unsigned int shift = 0;
      uint8_t c = 0;
      while ((c = bfd_get_8 (input_bfd, location + len++)) & 0x80)
        {
          if (shift < 8 * sizeof (x))
            x += (c & 0x7f) << shift;
          shift += 7;
        }
      if (shift < 8 * sizeof (x))
        x += (c & 0x7f) << shift;

      /* Put RELOCATION in the right bits.  */
      relocation >>= (bfd_vma) rightshift;
      relocation <<= (bfd_vma) bitpos;

      /* Add RELOCATION to the right bits of X.  */
      x = ((x & ~howto->dst_mask)
           | (((x & howto->src_mask) + relocation) & howto->dst_mask));

      for (i = 0; i < len-1; i++)
        {
          bfd_put_8 (input_bfd, 0x80 | (x & 0x7f), location + i);
          x >>= 7;
        }
      bfd_put_8 (input_bfd, (x & 0x7f), location + i);

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

/* Relocate a given location using a given value and howto.  */

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
                                   + address * bfd_octets_per_byte (input_bfd,
								    input_section));
}

/* Relocate a section while linking.  */

static bfd_boolean
elf32_wasm32_relocate_section (bfd *output_bfd ATTRIBUTE_UNUSED,
                               struct bfd_link_info *info, bfd *input_bfd,
                               asection *input_section, bfd_byte *contents,
                               Elf_Internal_Rela *relocs,
                               Elf_Internal_Sym *local_syms,
                               asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr = NULL;
  struct elf_link_hash_entry **sym_hashes = NULL;
  Elf_Internal_Rela *rel = NULL, *relend = NULL;
  bfd_vma *local_got_offsets = NULL;
  asection *sgot = NULL;
  asection *sreloc = NULL;
  struct dynamic_sections *ds = wasm32_create_dynamic_sections
    (output_bfd, info);
  struct elf_link_hash_table *htab = elf_hash_table (info);

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
      struct elf32_wasm32_link_hash_entry *hh;

      r_symndx = ELF32_R_SYM (rel->r_info);

      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_type == (int) R_WASM32_NONE)
        continue;

      howto = elf32_wasm32_howto_table + r_type;

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
	    {
	      fprintf (stderr, "no sym_hashes!\n");
	      return FALSE;
	    }

          h = sym_hashes[r_symndx - symtab_hdr->sh_info];
          hh = (struct elf32_wasm32_link_hash_entry *)h;
          while (h->root.type == bfd_link_hash_indirect
                 || h->root.type == bfd_link_hash_warning)
            {
              h = (struct elf_link_hash_entry *) h->root.u.i.link;
              hh = (struct elf32_wasm32_link_hash_entry *)h;
            }

          if (h->root.type == bfd_link_hash_defined
              || h->root.type == bfd_link_hash_defweak)
            {
              sec = h->root.u.def.section;
              /* The cases above are those in which relocation is
                 overwritten in the switch block below.  The cases
                 below are those in which we must defer relocation to
                 run-time, because we can't resolve absolute addresses
                 when creating a shared library.  */
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
                }
            }
          else if (h->root.type == bfd_link_hash_undefweak)
            ;
          else if (info->unresolved_syms_in_objects == RM_IGNORE
                   && ELF_ST_VISIBILITY (h->other) == STV_DEFAULT)
            {
	    }
          else if (!bfd_link_relocatable (info))
            (*info->callbacks->undefined_symbol)
              (info, hh->root.root.root.string,
	       input_bfd, input_section,
	       rel->r_offset, TRUE);
        }
      if (sec != NULL && discarded_section (sec))
        {
          _bfd_clear_contents (howto, input_bfd, input_section,
                               contents + rel->r_offset, 0);
          rel->r_info = 0;
          rel->r_addend = 0;

          continue;
        }

      if (bfd_link_relocatable (info))
        continue;

      switch ((int)r_type)
        {
        case R_WASM32_LEB128_PLT:
          /* Relocation is to the entry for this symbol in the
             procedure linkage table.  */

          /* Resolve a PLT reloc against a local symbol directly,
             without using the procedure linkage table.  */
          if (h == NULL)
            goto final_link_relocate;

          if (ELF_ST_VISIBILITY (h->other) == STV_INTERNAL
              || ELF_ST_VISIBILITY (h->other) == STV_HIDDEN)
	    {
	      /* We'd like to do this, but it causes invalid LEB128s
		 in our PLT section, where this symbol has already
		 been allocated.  */
              /* h->plt.offset = (bfd_vma) -1; */
	    }

          if (h->plt.offset != (bfd_vma) -1)
            {
              bfd_vma plt_bias = ds->spltidx->output_offset;
              bfd_vma plt_index = hh->plt_index;

              relocation = plt_index + plt_bias;
              addend = rel->r_addend;
            }
          else if (relocation == 0 && h->root.type == bfd_link_hash_undefweak)
            {
              /* This is a special case.  We don't know which function
                 signature the code expected, so we have to force this
                 block's return type to become unreachable.  Rather
                 than replacing the five bytes with a single LEB128
                 integer, we replace them with 5 zero bytes, the first
                 of which will be interpreted as LEB128; the rest will
                 become "unreachable" opcodes.  */
              /* Call __wasm_null */
              bfd_put_8 (abfd, 0, contents + rel->r_offset);
              /* Pad with "unreachable" opcodes.  */
              bfd_put_8 (abfd, 0, contents + rel->r_offset + 1);
              bfd_put_8 (abfd, 0, contents + rel->r_offset + 2);
              bfd_put_8 (abfd, 0, contents + rel->r_offset + 3);
              bfd_put_8 (abfd, 0, contents + rel->r_offset + 4);
	      r = bfd_reloc_ok;
              break;
            }

          goto final_link_relocate;

        case R_WASM32_LEB128_GOT:
        case R_WASM32_LEB128_GOT_CODE:
          /* Relocation is to the entry for this symbol in the global
             offset table.  */
          sgot = elf_hash_table (info)->sgot;
          BFD_ASSERT (sgot != NULL);

          if (h != NULL)
            {
              bfd_vma off;
              bfd_boolean dynamic_p;

              off = h->got.offset;
              if (off == (bfd_vma) -1)
                {
                  off = h->got.offset = sgot->size + (r_type == R_WASM32_LEB128_GOT_CODE ? 2 : 0);

                  if (h->dynindx == -1)
                    if (! bfd_elf_link_record_dynamic_symbol (info, h))
		      {
			fprintf (stderr, "failed to record dynamic symbol!\n");
			return FALSE;
		      }

                  sgot->size += 4;
                }
              BFD_ASSERT (off != (bfd_vma) -1);

              htab = elf_hash_table (info);
              dynamic_p = htab->dynamic_sections_created;
              if (! WILL_CALL_FINISH_DYNAMIC_SYMBOL (dynamic_p,
                                                     bfd_link_pic (info),
                                                     h)
                  || (bfd_link_pic (info)
                      && SYMBOL_REFERENCES_LOCAL (info, h))
                  || (ELF_ST_VISIBILITY (h->other)
                      && h->root.type == bfd_link_hash_undefweak))
                {
                  /* This is actually a static link, or it is a
                     -Bsymbolic link and the symbol is defined
                     locally, or the symbol was forced to be local
                     because of a version file.  We must initialize
                     this entry in the global offset table.  Since the
                     offset must always be a multiple of 4, we use the
                     least significant bit to record whether we have
                     initialized it already.

                     When doing a dynamic link, we create a .rela.got
                     relocation entry to initialize the value.  This
                     is done in the finish_dynamic_symbol routine.  */
                  if ((off & 1) != 0)
                    off &= ~1;
                  else
                    {
                      bfd_put_32 (output_bfd, relocation,
                                  sgot->contents + (off & -4));
                      h->got.offset |= 1;
                    }
                }
              relocation = /*sgot->output_offset XXX*/ + (off & -4);
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

                  fprintf (stderr, "unsupported relocation with addend against GOT symbol\n");
                  relocation += rel->r_addend;
                }
              else
                {
                  BFD_ASSERT (local_got_offsets != NULL
                              && local_got_offsets[r_symndx] != (bfd_vma) -1);

                  off = local_got_offsets[r_symndx];
                }

              if (off & 1)
                off &= ~1LL;
              else
                {
                  bfd_put_32 (output_bfd, relocation, sgot->contents + (off&-4));

                  if (bfd_link_pic (info))
                    {
                      asection *s;
                      Elf_Internal_Rela outrel;
                      bfd_byte *loc;

                      s = elf_hash_table (info)->srelgot;
                      BFD_ASSERT (s != NULL);

                      outrel.r_offset = (sgot->output_section->vma
                                         + sgot->output_offset
                                         + (off & -4));
                      outrel.r_info = ELF32_R_INFO (0, (r_type == R_WASM32_LEB128_GOT_CODE) ? R_WASM32_32_CODE : R_WASM32_REL32);
                      outrel.r_addend = relocation;
                      loc = s->contents;
                      loc += s->reloc_count++ * sizeof (Elf32_External_Rela);
                      bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);

                      BFD_ASSERT (s->size >= loc - s->contents + sizeof (Elf32_External_Rela));
                  }
                  local_got_offsets[r_symndx] |= 1;
                }
              relocation = sgot->output_offset + (off&-4);
            }
	  relocation += 0x40; /* XXX magic constant */

          goto final_link_relocate;

        case R_WASM32_32:
        case R_WASM32_32_CODE:
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
		    {
		      fprintf (stderr, "no sreloc section\n");
		      return FALSE;
		    }
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
                      outrel.r_info = ELF32_R_INFO (0, r_type);
                    }
                  else
                    {
                      BFD_ASSERT (h->dynindx != -1);
                      outrel.r_info = ELF32_R_INFO (h->dynindx, r_type);
                    }
                  outrel.r_addend = relocation;
                  addend = rel->r_addend;
                  outrel.r_addend
                    += (howto->partial_inplace
                        ? bfd_get_32 (input_bfd, contents + rel->r_offset)
                        : addend);
                }

              loc = sreloc->contents;
              loc += sreloc->reloc_count++ * sizeof (Elf32_External_Rela);
              bfd_elf32_swap_reloca_out (output_bfd, &outrel, loc);
              BFD_ASSERT (sreloc->size >= loc - sreloc->contents + sizeof (Elf32_External_Rela));

              /* If this reloc is against an external symbol, we do
                 not want to fiddle with the addend.  Otherwise, we
                 need to include the symbol value so that it becomes
                 an addend for the dynamic reloc.  */
              if (! relocate)
                continue;
            }
        /* FALLTHROUGH */
        case R_WASM32_LEB128:
        case R_WASM32_REL32:
          addend = rel->r_addend;
        final_link_relocate:
          r = wasm32_final_link_relocate (howto, input_bfd, input_section,
                                          contents, rel->r_offset,
                                          relocation, addend);
          break;

        case R_WASM32_CODE_POINTER:
        case R_WASM32_INDEX:
        case R_WASM32_PLT_SIG:
        case R_WASM32_PLT_INDEX:
          r = bfd_reloc_ok;
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
		      {
			fprintf (stderr, "no name in reloc overflow!\n");
			return FALSE;
		      }
                    if (*name == '\0')
                      name = bfd_section_name (sec);
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

#define ELF_ARCH		bfd_arch_wasm32
#define ELF_TARGET_ID		WASM_ELF_DATA
#define ELF_MACHINE_CODE	EM_WEBASSEMBLY
/* FIXME we don't have paged executables, see:
   https://github.com/pipcet/binutils-gdb/issues/4  */
#define ELF_MAXPAGESIZE		4096

#define TARGET_LITTLE_SYM       wasm32_elf32_vec
#define TARGET_LITTLE_NAME	"elf32-wasm32"

#define elf_backend_can_gc_sections          1
#define elf_backend_rela_normal              1
/* For testing.  */
#define elf_backend_want_dynrelro            1

#define elf_info_to_howto		elf32_wasm32_info_to_howto_rela
#define elf_info_to_howto_rel		NULL

#define bfd_elf32_bfd_reloc_type_lookup elf32_wasm32_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup elf32_wasm32_reloc_name_lookup

#define elf_backend_want_got_plt	1
#define elf_backend_plt_readonly	1
#define elf_backend_got_header_size	0
#define elf_backend_relocate_section	elf32_wasm32_relocate_section
#define elf_backend_check_relocs elf32_wasm32_check_relocs
#define elf_backend_adjust_dynamic_symbol    elf32_wasm32_adjust_dynamic_symbol
#define elf_backend_finish_dynamic_symbol    elf32_wasm32_finish_dynamic_symbol
#define elf_backend_create_dynamic_sections elf32_wasm32_create_dynamic_sections
#define elf_backend_finish_dynamic_sections  elf32_wasm32_finish_dynamic_sections
#define elf_backend_size_dynamic_sections    elf32_wasm32_size_dynamic_sections
#define elf_backend_want_got_plt 1
#define elf_backend_plt_readonly 1
#define elf_backend_got_header_size 0

#define bfd_elf32_bfd_link_hash_table_create \
                                        elf32_wasm32_link_hash_table_create
#include "elf32-target.h"
