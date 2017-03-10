#include "sysdep.h"
#include "alloca-conf.h"
#include "bfd.h"
#include "sysdep.h"
#include <limits.h>

#include "bfd.h"
#include "bfd_stdint.h"
#include "libiberty.h"
#include "libbfd.h"

#define bfd_wasm_close_and_cleanup                   _bfd_generic_close_and_cleanup
#define bfd_wasm_bfd_free_cached_info                _bfd_generic_bfd_free_cached_info
#define bfd_wasm_new_section_hook                    _bfd_generic_new_section_hook
#define bfd_wasm_bfd_is_local_label_name             bfd_generic_is_local_label_name
#define bfd_wasm_bfd_is_target_special_symbol       ((bfd_boolean (*) (bfd *, asymbol *)) bfd_false)
#define bfd_wasm_get_lineno                          _bfd_nosymbols_get_lineno
#define wasm_find_nearest_line                   _bfd_nosymbols_find_nearest_line
#define wasm_find_line                           _bfd_nosymbols_find_line
#define wasm_find_inliner_info                   _bfd_nosymbols_find_inliner_info
#define bfd_wasm_get_symbol_version_string          _bfd_nosymbols_get_symbol_version_string
#define wasm_bfd_make_debug_symbol               _bfd_nosymbols_bfd_make_debug_symbol
#define wasm_read_minisymbols                    _bfd_generic_read_minisymbols
#define wasm_minisymbol_to_symbol                _bfd_generic_minisymbol_to_symbol
#define bfd_wasm_set_arch_mach                       _bfd_generic_set_arch_mach
#define bfd_wasm_get_section_contents                _bfd_generic_get_section_contents
#define bfd_wasm_set_section_contents                _bfd_generic_set_section_contents
#define bfd_wasm_bfd_get_relocated_section_contents  bfd_generic_get_relocated_section_contents
#define bfd_wasm_bfd_relax_section                   bfd_generic_relax_section
#define bfd_wasm_bfd_gc_sections                     bfd_generic_gc_sections
#define bfd_wasm_bfd_lookup_section_flags            bfd_generic_lookup_section_flags
#define bfd_wasm_bfd_merge_sections                  bfd_generic_merge_sections
#define bfd_wasm_bfd_is_group_section                bfd_generic_is_group_section
#define bfd_wasm_bfd_discard_group                   bfd_generic_discard_group
#define bfd_wasm_section_already_linked              _bfd_generic_section_already_linked
#define bfd_wasm_bfd_define_common_symbol            bfd_generic_define_common_symbol
#define bfd_wasm_bfd_link_hash_table_create          _bfd_generic_link_hash_table_create
#define bfd_wasm_bfd_link_add_symbols                _bfd_generic_link_add_symbols
#define bfd_wasm_bfd_link_just_syms                  _bfd_generic_link_just_syms
#define bfd_wasm_bfd_copy_link_hash_symbol_type \
  _bfd_generic_copy_link_hash_symbol_type
#define bfd_wasm_bfd_final_link                      _bfd_generic_final_link
#define bfd_wasm_bfd_link_split_section              _bfd_generic_link_split_section
#define bfd_wasm_get_section_contents_in_window      _bfd_generic_get_section_contents_in_window
#define bfd_wasm_bfd_link_check_relocs               _bfd_generic_link_check_relocs


static bfd_boolean
wasm_get_magic (bfd *abfd, bfd_boolean *errorptr)
{
  bfd_byte magic[4];
  if (bfd_bread (magic, (bfd_size_type) 4, abfd) != 4)
    {
      if (bfd_get_error () != bfd_error_file_truncated)
        *errorptr = TRUE;
      return FALSE;
    }

  return TRUE;
}

static bfd_byte
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

static bfd_boolean
wasm_get_version (bfd *abfd, bfd_boolean *errorptr)
{
  bfd_byte vers[4];
  if (bfd_bread (vers, (bfd_size_type) 4, abfd) != 4)
    {
      *errorptr = TRUE;
      return FALSE;
    }

  if (vers[0] != 1 ||
      vers[1] || vers[2] || vers[3])
    return FALSE;

  return TRUE;
}

static const char *
wasm_section_code_to_name (bfd_byte section_code, bfd_boolean *errorptr)
{
  switch (section_code) {
  case 1:
    return "type";
  case 2:
    return "import";
  case 3:
    return "function";
  case 4:
    return "table";
  case 5:
    return "memory";
  case 6:
    return "global";
  case 7:
    return "export";
  case 8:
    return "start";
  case 9:
    return "element";
  case 10:
    return "code";
  case 11:
    return "data";
  default:
    *errorptr = TRUE;
    return NULL;
  }
}

static bfd_vma
wasm_get_uleb128 (bfd* abfd, bfd_boolean* error)
{
  bfd_byte byte;
  bfd_vma value = 0;
  int shift = 0;

  do {
    if (bfd_bread (&byte, 1, abfd) != 1)
      goto error_return;

    value += (byte & 0x7f) << shift;

    shift += 7;
  } while (byte & 0x80);

  return value;

 error_return:
  *error = TRUE;
  return (bfd_vma)-1;
}

#if 0
static bfd_boolean
wasm_skip_custom_section (bfd* abfd, bfd_boolean* error)
{
  bfd_vma len = wasm_get_uleb128(abfd, error);

  if (len != (bfd_vma) -1)
    {
      bfd_byte buf[8192];

      while (len > 8192)
        {
          if (bfd_bread (buf, 8192, abfd) != 8192)
            goto error_return;

          len -= 8192;
        }

      if (len > 0)
        if (bfd_bread (buf, len, abfd) != len)
          goto error_return;
    }
  else if (*error)
    {
      goto error_return;
    }

  return TRUE;

 error_return:
  *error = TRUE;

  return FALSE;
}
#endif

static bfd_boolean
bfd_wasm_read_header (bfd* abfd, bfd_boolean* error)
{
  if (!wasm_get_magic (abfd, error))
    goto error_return;

  if (!wasm_get_version (abfd, error))
    goto error_return;

  return TRUE;

 error_return:
  return FALSE;
}

static bfd_boolean
wasm_scan (bfd *abfd)
{
  bfd_boolean error = FALSE;
  bfd_vma vma = 0x80000000;
  bfd_byte section_code;

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0)
    goto error_return;

  if (!bfd_wasm_read_header (abfd, &error))
    goto error_return;

  while ((section_code = wasm_get_byte (abfd, &error)) != (bfd_byte)EOF)
    {
      asection *bfdsec;
      if (section_code)
        {
          const char *name = wasm_section_code_to_name (section_code, &error);
          char *secname;
          asprintf (&secname, ".wasm.%s", name);

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
          if (namelen == (bfd_vma)-1)
            goto error_return;
          char *name = xmalloc(namelen+1);
          name[namelen] = 0;
          if (bfd_bread (name, namelen, abfd) != namelen)
            goto error_return;

          char *secname;
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

      bfdsec->contents = xmalloc (bfdsec->size);
      if (bfdsec->size && !bfdsec->contents)
        goto error_return;

      if (bfd_bread (bfdsec->contents, bfdsec->size, abfd) != bfdsec->size)
        goto error_return;

      vma += bfdsec->size;
    }

  return TRUE;

 error_return:
  return FALSE;
}

static bfd_boolean
_bfd_wasm_write_object_contents (bfd* abfd __attribute__((unused)))
{
  return FALSE;
}

static bfd_boolean
wasm_mkobject (bfd *abfd __attribute__((unused)))
{
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
  return (abfd->symcount + 1) * (sizeof (asymbol));

}

static long
wasm_canonicalize_symtab (bfd *abfd, asymbol **table ATTRIBUTE_UNUSED)
{
  return bfd_get_symcount (abfd);
}

static asymbol *
wasm_make_empty_symbol (bfd *abfd ATTRIBUTE_UNUSED)
{
  bfd_size_type amt = sizeof (asymbol);
  asymbol *new_symbol = (asymbol *) bfd_zalloc (abfd, amt);

  if (!new_symbol)
    return NULL;
  new_symbol->the_bfd = abfd;
  return new_symbol;
}

static void
wasm_print_symbol (bfd *abfd ATTRIBUTE_UNUSED,
                   void * filep ATTRIBUTE_UNUSED,
                   asymbol *symbol ATTRIBUTE_UNUSED,
                   bfd_print_symbol_type how ATTRIBUTE_UNUSED)
{
}

static void
wasm_get_symbol_info (bfd *abfd ATTRIBUTE_UNUSED,
                      asymbol *symbol,
                      symbol_info *ret)
{
  bfd_symbol_info (symbol, ret);
}

#define wasm_get_symbol_version_string      _bfd_nosymbols_get_symbol_version_string
#define wasm_bfd_is_local_label_name               bfd_generic_is_local_label_name
#define wasm_bfd_is_target_special_symbol ((bfd_boolean (*) (bfd *, asymbol *)) bfd_false)


#define wasm_section_already_linked      _bfd_generic_section_already_linked
#define wasm_bfd_define_common_symbol     bfd_generic_define_common_symbol
#define wasm_bfd_discard_group            bfd_generic_discard_group
#define wasm_bfd_lookup_section_flags     bfd_generic_lookup_section_flags
#define wasm_bfd_final_link              _bfd_generic_final_link
#define wasm_bfd_link_split_section      _bfd_generic_link_split_section
#define wasm_bfd_link_check_relocs       _bfd_generic_link_check_relocs
#define wasm_bfd_link_just_syms          _bfd_generic_link_just_syms
#define wasm_bfd_is_group_section         bfd_generic_is_group_section
#define wasm_bfd_merge_sections           bfd_generic_merge_sections
#define wasm_bfd_gc_sections              bfd_generic_gc_sections
#define wasm_bfd_copy_link_hash_symbol_type _bfd_generic_copy_link_hash_symbol_type
#define wasm_bfd_link_just_syms          _bfd_generic_link_just_syms
#define wasm_bfd_link_add_symbols        _bfd_generic_link_add_symbols
#define wasm_bfd_link_hash_table_create  _bfd_generic_link_hash_table_create
#define wasm_bfd_relax_section            bfd_generic_relax_section
#define wasm_bfd_get_relocated_section_contents   bfd_generic_get_relocated_section_contents
#define wasm_get_lineno                           _bfd_nosymbols_get_lineno

static const bfd_target *
wasm_object_p (bfd *abfd)
{
  bfd_byte b[8];

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0
      || bfd_bread (b, (bfd_size_type) 8, abfd) != 8)
    return NULL;

  if (b[0] != 0 || b[1] != 'a' || b[2] != 's' || b[3] != 'm' ||
      b[4] != 1 || b[5] != 0 || b[6] != 0 || b[7] != 0)
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  if (! wasm_mkobject (abfd) || ! wasm_scan (abfd))
    return NULL;

  return abfd->xvec;
}

const bfd_target wasm_vec =
{
  "wasm",               /* Name */
  bfd_target_unknown_flavour,
  BFD_ENDIAN_LITTLE,
  BFD_ENDIAN_LITTLE,
  (WP_TEXT),             /* Object flags. */
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
    bfd_false, /* wasm_mkobject, */
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
  BFD_JUMP_TABLE_WRITE (_bfd_generic),
  BFD_JUMP_TABLE_LINK (wasm),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,

  NULL,
};
