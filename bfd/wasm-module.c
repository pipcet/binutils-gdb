/* BFD back-end for WebAssembly modules.
   Copyright (C) 1990-2017 Free Software Foundation, Inc.

   Based on srec.c, mmo.c, and binary.c

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
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/* The WebAssembly module format is a simple object file format
 * including up to 11 numbered sections, plus any number of named
 * "custom" sections. It is described at
 * https://github.com/WebAssembly/design/blob/master/BinaryEncoding.md. */

#include "sysdep.h"
#include "alloca-conf.h"
#include "bfd.h"
#include "sysdep.h"
#include <limits.h>
#include "bfd_stdint.h"
#include "libiberty.h"
#include "libbfd.h"
#include "wasm-module.h"

/* From elf-eh-frame.c: */
/* If *ITER hasn't reached END yet, read the next byte into *RESULT and
   move onto the next byte.  Return true on success.  */

static inline bfd_boolean
read_byte (bfd_byte **iter, bfd_byte *end, unsigned char *result)
{
  if (*iter >= end)
    return FALSE;
  *result = *((*iter)++);
  return TRUE;
}

/* Move *ITER over LENGTH bytes, or up to END, whichever is closer.
   Return true it was possible to move LENGTH bytes.  */

static inline bfd_boolean
skip_bytes (bfd_byte **iter, bfd_byte *end, bfd_size_type length)
{
  if ((bfd_size_type) (end - *iter) < length)
    {
      *iter = end;
      return FALSE;
    }
  *iter += length;
  return TRUE;
}

/* Move *ITER over an leb128, stopping at END.  Return true if the end
   of the leb128 was found.  */

static bfd_boolean
skip_leb128 (bfd_byte **iter, bfd_byte *end)
{
  unsigned char byte;
  do
    if (!read_byte (iter, end, &byte))
      return FALSE;
  while (byte & 0x80);
  return TRUE;
}

/* Like skip_leb128, but treat the leb128 as an unsigned value and
   store it in *VALUE.  */

static bfd_boolean
read_uleb128 (bfd_byte **iter, bfd_byte *end, bfd_vma *value)
{
  bfd_byte *start, *p;

  start = *iter;
  if (!skip_leb128 (iter, end))
    return FALSE;

  p = *iter;
  *value = *--p;
  while (p > start)
    *value = (*value << 7) | (*--p & 0x7f);

  return TRUE;
}

/* Read an unsigned leb128 from ABFD, setting ERROR to true if there
   was an error. */
static bfd_vma
wasm_get_uleb128 (bfd* abfd, bfd_boolean* error)
{
  bfd_byte byte;
  bfd_vma value = 0;
  int shift = 0;

  do
    {
      if (bfd_bread (&byte, 1, abfd) != 1)
        goto error_return;

      value += (byte & 0x7f) << shift;

      shift += 7;
    }
  while (byte & 0x80);

  return value;

 error_return:
  *error = TRUE;
  return (bfd_vma)-1;
}

/* Write an unsigned leb128 V to ABFD, return true on success. */
static bfd_boolean
bfd_write_uleb128 (bfd *abfd, bfd_vma v)
{
  do
    {
      bfd_byte c = v & 0x7f;
      v >>= 7;

      if (v)
        c |= 0x80;

      if (bfd_bwrite (&c, 1, abfd) != 1)
        return FALSE;
    }
  while (v);

  return TRUE;
}

typedef struct
{
  asymbol *symbols;
  bfd_size_type symcount;
} tdata_type;

static bfd_boolean
wasm_get_magic (bfd *abfd, bfd_boolean *errorptr)
{
  bfd_byte magic_const[] = WASM_MAGIC;
  bfd_byte magic[4];

  if (bfd_bread (magic, (bfd_size_type) 4, abfd) != 4)
    {
      *errorptr = TRUE;
      return FALSE;
    }

  if (memcmp (magic, magic_const, 4) != 0)
    {
      *errorptr = TRUE;
      return FALSE;
    }

  return TRUE;
}

/* Read a byte from ABFD and return it, or EOF for EOF or error. Set
   ERRORPTR on non-EOF error. */
static int
wasm_get_byte (bfd *abfd, bfd_boolean *errorptr)
{
  bfd_byte byte;
  if (bfd_bread (&byte, (bfd_size_type) 1, abfd) != 1)
    {
      if (bfd_get_error () != bfd_error_file_truncated)
        *errorptr = TRUE;
      return EOF;
    }

  return byte;
}

/* Read the version word from ABFD, returning true if it's a supported
   version. Set ERRORPTR otherwise. */
static bfd_boolean
wasm_get_version (bfd *abfd, bfd_boolean *errorptr)
{
  bfd_byte vers[4];n
  bfd_byte vers_const = WASM_VERSION;
  if (bfd_bread (vers, (bfd_size_type) 4, abfd) != 4)
    {
      *errorptr = TRUE;
      return FALSE;
    }

  /* Don't attempt to parse newer versions, which are likely to
   * require code changes. */
  if (memcmp (vers, vers_const, 4) != 0)
    {
      *errorptr = TRUE;
      return FALSE;
    }

  return TRUE;
}

static const char * const wasm_numbered_sections[] = {
  NULL, /* custom section, different layout */
  WASM_SECTION( 1, type),
  WASM_SECTION( 2, import),
  WASM_SECTION( 3, function),
  WASM_SECTION( 4, table),
  WASM_SECTION( 5, memory),
  WASM_SECTION( 6, global),
  WASM_SECTION( 7, export),
  WASM_SECTION( 8, start),
  WASM_SECTION( 9, element),
  WASM_SECTION(10, code),
  WASM_SECTION(11, data),
};

#define WASM_NUMBERED_SECTIONS (sizeof(wasm_numbered_sections) / sizeof(wasm_numbered_sections[0]))

/* Resolve SECTION_CODE to a section name if there is one, NULL
   otherwise. */
static const char *
wasm_section_code_to_name (bfd_byte section_code)
{
  if (section_code < WASM_NUMBERED_SECTIONS)
    {
      return wasm_numbered_sections[section_code];
    }

  return NULL;
}

/* Translate section name NAME to a section code, or -1 if it's a
   custom name. */
static int
wasm_section_name_to_code (const char *name)
{
  unsigned i;
  for (i = 1; i < WASM_NUMBERED_SECTIONS; i++)
    {
      if (strcmp (name, wasm_numbered_sections[i]) == 0)
        return i;
    }

  return -1;
}

static bfd_boolean
bfd_wasm_read_header (bfd *abfd, bfd_boolean *error)
{
  if (!wasm_get_magic (abfd, error))
    return FALSE;

  if (!wasm_get_version (abfd, error))
    return FALSE;

  return TRUE;
}

/* Scan the "function" subsection of the "name" section ASECT in the
   wasm module ABFD. Create symbols. Return true on success. */
static bfd_boolean
wasm_scan_name_function_section (bfd *abfd, sec_ptr asect,
                                 void *data ATTRIBUTE_UNUSED)
{
  bfd_byte *p;
  bfd_byte *end;
  bfd_vma payload_size;
  bfd_vma symcount = 0;
  tdata_type *tdata = abfd->tdata.any;
  bfd_size_type sym_allocated = 0;
  asymbol *symbols = NULL;
  sec_ptr space_function_index;
  unsigned int length_read;
  bfd_vma i;

  if (!asect)
    return FALSE;

  if (strcmp (asect->name, ".wasm.name") != 0)
    return FALSE;

  p = asect->contents;
  end = asect->contents + asect->size;

  if (!p)
    return FALSE;

  while (p < end)
    {
      if (*p++ == 1)
        break;

      payload_size = _bfd_safe_read_leb128 (abfd, p, &length_read,
                                            false, end);
      if (length_read == 0)
        return FALSE;

      if (p > p + payload_size)
        return FALSE;

      p += payload_size;
    }

  if (p >= end)
    return FALSE;

  payload_size = _bfd_safe_read_leb128 (abfd, p, &length_read,
                                        false, end);

  if (length_read == 0)
    return FALSE;

  if (p > p + payload_size)
    return FALSE;

  if (p + payload_size > end)
    return FALSE;

  end = p + payload_size;

  if (!read_uleb128 (&p, end, &symcount))
    return FALSE;

  tdata->symcount = symcount;
  symcount = 0;

  space_function_index = bfd_make_section_with_flags (abfd, WASM_SECTION_FUNCTION_INDEX, SEC_READONLY | SEC_CODE);
  if (!space_function_index)
    space_function_index = bfd_get_section_by_name (abfd, WASM_SECTION_FUNCTION_INDEX);

  for (i = 0; p < end && i < tdata->symcount; i++)
    {
      bfd_vma index;
      bfd_vma len;
      char *name;
      asymbol *sym;

      index = _bfd_safe_read_leb128 (abfd, p, &length_read,
                                     false, end);

      if (length_read == 0)
        goto error_out;

      p += length_read;

      len = _bfd_safe_read_leb128 (abfd, p, &length_read,
                                   false, end);

      if (length_read == 0)
        goto error_out;

      p += length_read;

      if (!read_uleb128 (&p, end, &index)
          || !read_uleb128 (&p, end, &len))
        return FALSE;

      name = bfd_alloc (abfd, len + 1);

      name[len] = 0;

      memcpy (name, p, len);

      p += len;

      if (symcount == sym_allocated)
        {
          sym_allocated *= 2;
          if (sym_allocated == 0)
            sym_allocated = 512;

          symbols = bfd_realloc_or_free (symbols, sym_allocated * sizeof (asymbol));
          if (!symbols)
            return FALSE;
        }

      sym = &symbols[symcount++];
      sym->the_bfd = abfd;
      sym->name = name;
      sym->value = index;
      sym->flags = BSF_GLOBAL | BSF_FUNCTION;
      sym->section = space_function_index;
      sym->udata.p = NULL;
    }

  if (i < tdata->symcount)
    {
      free (symbols);
      return FALSE;
    }

  tdata->symbols = symbols;
  tdata->symcount = symcount;
  abfd->symcount = symcount;

  return TRUE;

 error_out:
  free (symbols);
  return FALSE;
}

/* Scan the wasm module ABFD. Return true on success. */
static bfd_boolean
wasm_scan (bfd *abfd)
{
  bfd_boolean error = FALSE;
  bfd_vma vma = 0x80000000;
  int section_code;

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0)
    goto error_return;

  if (!bfd_wasm_read_header (abfd, &error))
    goto error_return;

  while ((section_code = wasm_get_byte (abfd, &error)) != EOF)
    {
      asection *bfdsec;
      if (section_code)
        {
          const char *name = wasm_section_code_to_name (section_code);
          char *secname;

          if (!name)
            goto error_return;

          secname = strdup (name);

          bfdsec = bfd_make_section_anyway_with_flags (abfd, secname, SEC_HAS_CONTENTS);
          if (bfdsec == NULL)
            goto error_return;

          bfdsec->vma = vma;
          bfdsec->lma = vma;
          bfdsec->size = wasm_get_uleb128 (abfd, &error);
          bfdsec->filepos = bfd_tell (abfd);
          bfdsec->alignment_power = 0;
        }
      else
        {
          bfd_vma payload_len = wasm_get_uleb128 (abfd, &error);
          file_ptr section_start = bfd_tell (abfd);
          bfd_vma namelen = wasm_get_uleb128 (abfd, &error);
          char *name;
          char *secname;

          if (namelen == (bfd_vma)-1)
            goto error_return;
          name = bfd_zalloc (abfd, namelen+1);
          if (! name)
            goto error_return;
          name[namelen] = 0;
          if (bfd_bread (name, namelen, abfd) != namelen)
            goto error_return;

          asprintf (&secname, ".wasm.%s", name);

          bfdsec = bfd_make_section_anyway_with_flags (abfd, secname, SEC_HAS_CONTENTS);
          if (bfdsec == NULL)
            goto error_return;

          bfdsec->vma = vma;
          bfdsec->lma = vma;
          bfdsec->size = payload_len - bfd_tell (abfd) + section_start;
          bfdsec->filepos = bfd_tell (abfd);
          bfdsec->alignment_power = 0;
        }

      bfdsec->contents = bfd_zalloc (abfd, bfdsec->size);
      if (bfdsec->size && !bfdsec->contents)
        goto error_return;

      if (bfd_bread (bfdsec->contents, bfdsec->size, abfd) != bfdsec->size)
        goto error_return;

      vma += bfdsec->size;
    }

  /* Make sure we're at actual EOF. There's no indication in the
   * WebAssembly format of how long the file is supposed to be. */
  if (error)
    goto error_return;

  if (!wasm_scan_name_function_section (abfd, bfd_get_section_by_name (abfd, ".wasm.name"), NULL))
    {
      /* An invalid name section does not make the entire module
       * invalid. */
      return TRUE;
    }

  return TRUE;

 error_return:
  return FALSE;
}

static void
wasm_register_section (bfd *abfd ATTRIBUTE_UNUSED,
                       asection *asect, void *fsarg)
{
  sec_ptr *numbered_sections = fsarg;
  int index = wasm_section_name_to_code (asect->name);

  if (index == -1)
    return;

  numbered_sections[index] = asect;
}

struct compute_section_arg
{
  bfd_vma pos;
  bfd_boolean failed;
};

static void
wasm_compute_custom_section_file_position (bfd *abfd, sec_ptr asect,
                                           void *fsarg)
{
  struct compute_section_arg *fs = fsarg;
  int index;

  if (fs->failed)
    return;

  index = wasm_section_name_to_code (asect->name);

  if (index != -1)
    return;

  if (CONST_STRNEQ (asect->name, ".wasm."))
    {
      const char *name = asect->name + strlen (".wasm.");
      bfd_size_type payload_len = asect->size;
      bfd_size_type name_len = strlen (name);
      bfd_size_type nl = name_len;

      payload_len += name_len;

      do
        {
          payload_len++;
          nl >>= 7;
        }
      while (nl);

      bfd_seek (abfd, fs->pos, SEEK_SET);
      if (!bfd_write_uleb128 (abfd, 0) ||
          !bfd_write_uleb128 (abfd, payload_len) ||
          !bfd_write_uleb128 (abfd, name_len) ||
          bfd_bwrite (name, name_len, abfd) != name_len)
        goto error_return;
      fs->pos = asect->filepos = bfd_tell (abfd);
    }
  else
    {
      asect->filepos = fs->pos;
    }


  fs->pos += asect->size;

  return;

 error_return:
  fs->failed = TRUE;
  return;
}

static bfd_boolean
wasm_compute_section_file_positions (bfd *abfd)
{
  bfd_byte magic[] = WASM_MAGIC;
  bfd_byte vers[] = WASM_VERSION;
  sec_ptr numbered_sections[WASM_NUMBERED_SECTIONS+1];
  struct compute_section_arg fs;

  bfd_seek (abfd, (bfd_vma) 0, SEEK_SET);

  if (bfd_bwrite (magic, 4, abfd) != 4
      || bfd_bwrite (vers, 4, abfd) != 4)
    return FALSE;

  for (unsigned i = 0; i < WASM_NUMBERED_SECTIONS; i++)
    numbered_sections[i] = 0;

  bfd_map_over_sections (abfd, wasm_register_section, numbered_sections);

  fs.pos = 8;
  for (unsigned i = 0; i < WASM_NUMBERED_SECTIONS; i++)
    {
      sec_ptr sec = numbered_sections[i];
      bfd_size_type size;

      if (!sec)
        continue;
      size = sec->size;
      bfd_seek (abfd, fs.pos, SEEK_SET);
      if (!bfd_write_uleb128 (abfd, i)
          || !bfd_write_uleb128 (abfd, size))
        return FALSE;
      fs.pos = sec->filepos = bfd_tell (abfd);
      fs.pos += size;
    }

  fs.failed = FALSE;

  bfd_map_over_sections (abfd, wasm_compute_custom_section_file_position, &fs);

  if (fs.failed)
    return FALSE;

  return TRUE;
}


static bfd_boolean
wasm_set_section_contents (bfd *abfd,
                           sec_ptr section,
                           const void *location,
                           file_ptr offset,
                           bfd_size_type count)
{
  if (count == 0)
    return TRUE;

  if (!abfd->output_has_begun
      && !wasm_compute_section_file_positions (abfd))
    return FALSE;

  if (bfd_seek (abfd, section->filepos + offset, SEEK_SET) != 0
      || bfd_bwrite (location, count, abfd) != count)
    return FALSE;

  return TRUE;
}

static bfd_boolean
_bfd_wasm_write_object_contents (bfd* abfd)
{
  bfd_byte magic[] = WASM_MAGIC;
  bfd_byte vers[] = WASM_VERSION;

  if (bfd_seek (abfd, 0, SEEK_SET) != 0)
    return FALSE;

  if (bfd_bwrite (magic, 4, abfd) != 4
      || bfd_bwrite (vers, 4, abfd) != 4)
    return FALSE;

  return TRUE;
}

static bfd_boolean
wasm_mkobject (bfd *abfd)
{
  tdata_type *tdata = (tdata_type *) bfd_alloc (abfd, sizeof (tdata_type));

  if (!tdata)
    return FALSE;

  tdata->symbols = NULL;
  tdata->symcount = 0;

  abfd->tdata.any = tdata;

  return TRUE;
}

static int
wasm_sizeof_headers (bfd *abfd ATTRIBUTE_UNUSED,
                     struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return 8;
}

static long
wasm_get_symtab_upper_bound (bfd *abfd)
{
  tdata_type *tdata = abfd->tdata.any;

  return (tdata->symcount + 1) * (sizeof (asymbol));
}

static long
wasm_canonicalize_symtab (bfd *abfd, asymbol **alocation)
{
  tdata_type *tdata = abfd->tdata.any;
  size_t i;

  for (i = 0; i < tdata->symcount; i++)
    alocation[i] = &tdata->symbols[i];
  alocation[i] = NULL;

  return tdata->symcount;
}

static asymbol *
wasm_make_empty_symbol (bfd *abfd)
{
  bfd_size_type amt = sizeof (asymbol);
  asymbol *new_symbol = (asymbol *) bfd_zalloc (abfd, amt);

  if (!new_symbol)
    return NULL;
  new_symbol->the_bfd = abfd;
  return new_symbol;
}

static void
wasm_print_symbol (bfd *abfd,
                   void * filep,
                   asymbol *symbol,
                   bfd_print_symbol_type how)
{
  FILE *file = (FILE *) filep;

  switch (how)
    {
    case bfd_print_symbol_name:
      fprintf (file, "%s", symbol->name);
      break;

    default:
      bfd_print_symbol_vandf (abfd, filep, symbol);
      fprintf (file, " %-5s %s", symbol->section->name, symbol->name);
    }
}

static void
wasm_get_symbol_info (bfd *abfd ATTRIBUTE_UNUSED,
                      asymbol *symbol,
                      symbol_info *ret)
{
  bfd_symbol_info (symbol, ret);
}

static const bfd_target *
wasm_object_p (bfd *abfd)
{
  bfd_boolean error;

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0)
    return NULL;

  if (!bfd_wasm_read_header (bfd, &error))
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  if (! wasm_mkobject (abfd) || ! wasm_scan (abfd))
    return NULL;

  if (! bfd_default_set_arch_mach (abfd, bfd_arch_wasm32, 0))
    return NULL;

  if (abfd->symcount > 0)
    abfd->flags |= HAS_SYMS;

  return abfd->xvec;
}

/* BFD_JUMP_TABLE_WRITE */
#define wasm_set_arch_mach                       _bfd_generic_set_arch_mach

/* BFD_JUMP_TABLE_SYMBOLS */
#define wasm_get_symbol_version_string    _bfd_nosymbols_get_symbol_version_string
#define wasm_bfd_is_local_label_name       bfd_generic_is_local_label_name
#define wasm_bfd_is_target_special_symbol ((bfd_boolean (*) (bfd *, asymbol *)) bfd_false)
#define wasm_get_lineno                   _bfd_nosymbols_get_lineno
#define wasm_find_nearest_line            _bfd_nosymbols_find_nearest_line
#define wasm_find_line                    _bfd_nosymbols_find_line
#define wasm_find_inliner_info            _bfd_nosymbols_find_inliner_info
#define wasm_bfd_make_debug_symbol        _bfd_nosymbols_bfd_make_debug_symbol
#define wasm_read_minisymbols             _bfd_generic_read_minisymbols
#define wasm_minisymbol_to_symbol         _bfd_generic_minisymbol_to_symbol

/* BFD_JUMP_TABLE_LINK */
#define wasm_bfd_get_relocated_section_contents   bfd_generic_get_relocated_section_contents
#define wasm_bfd_relax_section            bfd_generic_relax_section
#define wasm_bfd_gc_sections              bfd_generic_gc_sections
#define wasm_bfd_lookup_section_flags     bfd_generic_lookup_section_flags
#define wasm_bfd_merge_sections           bfd_generic_merge_sections
#define wasm_bfd_is_group_section         bfd_generic_is_group_section
#define wasm_bfd_discard_group            bfd_generic_discard_group
#define wasm_bfd_link_hash_table_create  _bfd_generic_link_hash_table_create
#define wasm_bfd_link_add_symbols        _bfd_generic_link_add_symbols
#define wasm_bfd_link_just_syms          _bfd_generic_link_just_syms
#define wasm_bfd_copy_link_hash_symbol_type _bfd_generic_copy_link_hash_symbol_type
#define wasm_bfd_final_link              _bfd_generic_final_link
#define wasm_bfd_link_split_section      _bfd_generic_link_split_section
#define wasm_section_already_linked      _bfd_generic_section_already_linked
#define wasm_bfd_define_common_symbol     bfd_generic_define_common_symbol
#define wasm_bfd_link_check_relocs       _bfd_generic_link_check_relocs

const bfd_target wasm_vec =
{
  "wasm",               /* Name */
  bfd_target_unknown_flavour,
  BFD_ENDIAN_LITTLE,
  BFD_ENDIAN_LITTLE,
  (HAS_SYMS | WP_TEXT),             /* Object flags. */
  (SEC_CODE | SEC_DATA | SEC_HAS_CONTENTS), /* Section flags */
  0,                    /* Leading underscore */
  ' ',                  /* AR_pad_char */
  255,                  /* AR_max_namelen */
  0,				/* match priority.  */
  /* Routines to byte-swap various sized integers from the data sections */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16,

  /* Routines to byte-swap various sized integers from the file headers */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16,

  {
    _bfd_dummy_target,
    wasm_object_p,	/* bfd_check_format.  */
    _bfd_dummy_target,
    _bfd_dummy_target,
  },
  {
    bfd_false,
    wasm_mkobject,
    _bfd_generic_mkarchive,
    bfd_false,
  },
  {				/* bfd_write_contents.  */
    bfd_false,
    _bfd_wasm_write_object_contents,
    _bfd_write_archive_contents,
    bfd_false,
  },

  BFD_JUMP_TABLE_GENERIC (_bfd_generic),
  BFD_JUMP_TABLE_COPY (_bfd_generic),
  BFD_JUMP_TABLE_CORE (_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
  BFD_JUMP_TABLE_SYMBOLS (wasm),
  BFD_JUMP_TABLE_RELOCS (_bfd_norelocs),
  BFD_JUMP_TABLE_WRITE (wasm),
  BFD_JUMP_TABLE_LINK (wasm),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,

  NULL,
};
