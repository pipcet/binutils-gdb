#include "sysdep.h"
#include "bfd.h"
#include "elf-bfd.h"
#include "progress.h"
#include "bucomm.h"
#include "getopt.h"
#include "libiberty.h"

#include <stdio.h>

static int exit_status = 0;

static char *default_target = NULL;

static int show_version = 0;

static struct option long_options[]=
{
  {0, no_argument, 0, 0}
};

static void usage (FILE *, int) ATTRIBUTE_NORETURN;
static void
usage (FILE *stream, int status)
{
  fprintf (stream, _("Usage: %s <option(s)> <file(s)>\n"), program_name);
  fprintf (stream, _("\
  -t, --syms               Display the contents of the symbol table(s)\n\
  -T, --dynamic-syms       Display the contents of the dynamic symbol table\n\
  -r, --reloc              Display the relocation entries in the file\n\
  -R, --dynamic-reloc      Display the dynamic relocation entries in the file\n\
  -v, --version            Display this program's version number\n\
  -i, --info               List object formats and architectures supported\n\
  -H, --help               Display this information\n\
"));
  if (status != 2)
    {
      fprintf (stream, _("\n The following switches are optional:\n"));
      fprintf (stream, _("\
  -b, --target=BFDNAME           Specify the target object format as BFDNAME\n\
  -m, --architecture=MACHINE     Specify the target architecture as MACHINE\n"));

      list_supported_targets (program_name, stream);
      list_supported_architectures (program_name, stream);
    }
  if (REPORT_BUGS_TO[0] && status == 0)
    fprintf (stream, _("Report bugs to %s.\n"), REPORT_BUGS_TO);
  exit (status);
}

static bfd_boolean
print_symbol (bfd *abfd, asymbol *sy, FILE *f, const char *init)
{
  const char *name = sy->name;
  const char *section_name = NULL;
  const char *version_string;

  if (sy->section)
    section_name = sy->section->name;

  bfd_vma value = sy->value + (sy->section ? sy->section->vma : 0);
  flagword type = sy->flags;

  if (type & BSF_LOCAL)
    return FALSE;

  if (!(type & BSF_DYNAMIC))
    return FALSE;

  bfd_vma size = ((elf_symbol_type *) sy)->internal_elf_sym.st_size;
  bfd_boolean hidden;
  version_string = _bfd_elf_get_symbol_version_string (abfd, sy, TRUE,
						       &hidden);
  unsigned char st_other = ((elf_symbol_type *) sy)->internal_elf_sym.st_other;

  bfd_boolean first = TRUE;
  if (name)
    {
      fprintf (f, "%s", init);
      fprintf (f, "    \"%s\":{", name);
    }
  else
    return FALSE;
  if (section_name)
    {
      fprintf (f, "%s\"section\":\"%s\"",
	       first ? "" : ",", section_name);
      first = FALSE;
    }
  {
    bfd_boolean first2 = TRUE;
    fprintf (f, "%s\"flags\":[", first ? "" : ",");
    if (type & BSF_LOCAL)
      {
	fprintf (f, "%s\"local\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_GLOBAL)
      {
	fprintf (f, "%s\"global\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_GNU_UNIQUE)
      {
	fprintf (f, "%s\"gnu_unique\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_WEAK)
      {
	fprintf (f, "%s\"weak\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_CONSTRUCTOR)
      {
	fprintf (f, "%s\"constructor\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_WARNING)
      {
	fprintf (f, "%s\"warning\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_INDIRECT)
      {
	fprintf (f, "%s\"indirect\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_GNU_INDIRECT_FUNCTION)
      {
	fprintf (f, "%s\"gnu_indirect_function\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_DEBUGGING)
      {
	fprintf (f, "%s\"debugging\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_DYNAMIC)
      {
	fprintf (f, "%s\"dynamic\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_FUNCTION)
      {
	fprintf (f, "%s\"function\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_FILE)
      {
	fprintf (f, "%s\"file\"", first2 ? "" : ","); first2 = FALSE;
      }
    if (type & BSF_OBJECT)
      {
	fprintf (f, "%s\"object\"", first2 ? "" : ","); first2 = FALSE;
      }
    fprintf (f, "]");
    first = FALSE;
  }
  {
    fprintf (f, "%s\"value\":%lld",
	     first ? "" : ",", (long long) value);
    first = FALSE;
  }
  {
    fprintf (f, "%s\"size\":%lld",
	     first ? "" : ",", (long long) size);
    first = FALSE;
  }
  if (version_string)
    {
      fprintf (f, "%s\"version\":\"%s\"",
	       first ? "" : ",", version_string);
      first = FALSE;
    }
  switch (st_other)
    {
    case STV_INTERNAL:
      {
	fprintf (f, "%s\"visibility\":\"internal\"", first ? "" : ",");
	first = FALSE;
	break;
      }
    case STV_HIDDEN:
      {
	fprintf (f, "%s\"visibility\":\"hidden\"", first ? "" : ",");
	first = FALSE;
	break;
      }
    case STV_PROTECTED:
      {
	fprintf (f, "%s\"visibility\":\"protected\"", first ? "" : ",");
	first = FALSE;
	break;
      }
    default:
      ;
    }
  fprintf (f, "}");
  return TRUE;
}

static void
print_symtab (asymbol **sy, long n, FILE *f)
{
  const char *init = "";
  for (long i = 0; i < n; i++)
    {
      asymbol *current = sy[i];
      bfd *cur_bfd = bfd_asymbol_bfd (current);
      if (!cur_bfd)
	{
	  printf (_("could not determine the type of symbol number %ld\n"),
		  i);
	  continue;
	}
      if (print_symbol (cur_bfd, current, f, init))
	init = ",\n";
    }
}

static void
do_symtab (bfd *abfd, FILE *f)
{
  asymbol **sy = NULL;
  long storage;

  if (!(bfd_get_file_flags (abfd) & HAS_SYMS))
    {
      return;
    }

  storage = bfd_get_symtab_upper_bound (abfd);
  if (storage < 0)
    {
      non_fatal (_("failed to read symbol table from: %s"), bfd_get_filename (abfd));
      bfd_fatal (_("error message was"));
    }
  if (storage)
    sy = (asymbol **) xmalloc (storage);

  long n = bfd_canonicalize_symtab (abfd, sy);
  if (n < 0)
    bfd_fatal (bfd_get_filename (abfd));

  print_symtab (sy, n, f);

  free (sy);
}
static int
symbol_compare (const void *a, const void *b, void *c)
{
  asymbol *sya = *(asymbol **) a;
  asymbol *syb = *(asymbol **) b;
  struct bfd *abfd = (struct bfd *) c;
  (void) abfd;

  return strcmp (sya->name, syb->name);
}

static int
relent_compare (const void *a, const void *b, void *c)
{
  arelent *sya = *(arelent **) a;
  arelent *syb = *(arelent **) b;
  struct bfd *abfd = (struct bfd *) c;
  (void) abfd;

  int diff = sya->address - syb->address;

  return diff;
}

static void
do_dynamic_symtab (bfd *abfd, FILE *f)
{
  asymbol **sy = NULL;
  long storage;

  if (!(bfd_get_file_flags (abfd) & DYNAMIC))
    {
      return;
    }

  storage = bfd_get_dynamic_symtab_upper_bound (abfd);
  if (storage < 0)
    {

      bfd_fatal (bfd_get_filename (abfd));
    }
  if (storage)
    sy = (asymbol **) xmalloc (storage);

  long n_sym = bfd_canonicalize_dynamic_symtab (abfd, sy);
  if (n_sym < 0)
    bfd_fatal (bfd_get_filename (abfd));


  arelent **rel = NULL;
  storage = bfd_get_dynamic_reloc_upper_bound (abfd);
  if (storage < 0)
    bfd_fatal (bfd_get_filename (abfd));

  rel = xmalloc (storage);
  long n = bfd_canonicalize_dynamic_reloc (abfd, rel, sy);

  qsort_r (sy, n_sym, sizeof (sy[0]),
	   symbol_compare, abfd);
  fprintf (f, "  \"dynamic_symtab\": {\n");
  print_symtab (sy, n_sym, f);
  fprintf (f, "\n  }");
  if (n)
    fprintf (f, ",\n  \"dynamic_relocs\": [\n");
  qsort_r (rel, n, sizeof (rel[0]),
	   relent_compare, abfd);
  const char *init = "";
  for (long i = 0; i < n; i++)
    {
      arelent *current = rel[i];
      const char *sym_name = NULL;
      const char *section_name = NULL;
      if (current->sym_ptr_ptr && *current->sym_ptr_ptr)
	{
	  sym_name = (*(current->sym_ptr_ptr))->name;
	  section_name = (*(current->sym_ptr_ptr))->section->name;
	}

      if (current->howto && strcmp (current->howto->name, "R_WASM32_NONE") == 0)
	continue;
      fprintf (f, "%s    {", init);
      fprintf (f, "\"addr\":%lld", (long long) current->address);
      if (current->howto)
	{
	  if (current->howto->name)
	    fprintf (f, ",\"type\":\"%s\"", current->howto->name);
	  else
	    fprintf (f, ",\"type\":%lld", (long long) current->howto->type);
	}
      if (strcmp (sym_name, "*ABS*") != 0
	  || strcmp (section_name, "*ABS*") != 0)
	{
	  if (sym_name)
	    fprintf (f, ",\"symbol\":\"%s\"", sym_name);
	  if (section_name)
	    fprintf (f, ",\"section\":\"%s\"", section_name);
	}
      bfd_signed_vma addend = current->addend;
      fprintf (f, ",\"addend\":%lld", (long long) addend);
      fprintf (f, "}\n");
      init = ",\n";
    }
  fprintf (f, "\n  ]");

  struct bfd_link_needed_list *needed;
  if (bfd_elf_get_bfd_needed_list (abfd, &needed)
      && needed != NULL)
    {
      const char *init2 = "";
      fprintf (f, ",\n  \"needed\":[\n");
      for (struct bfd_link_needed_list *l = needed; l != NULL; l = l->next)
	{
	  fprintf (f, "%s    \"%s\"", init2, l->name);
	  init2 = ",\n";
	}
      fprintf (f, "\n  ]");
    }

  fprintf (f, "\n");
  free (sy);
}

static void
dyninfo (bfd *abfd, FILE *f)
{
  fprintf (f, "{\n");
  do_dynamic_symtab (abfd, f);
  if (FALSE)
    do_symtab (abfd, f);
  fprintf (f, "}\n");
}

static void
do_file (char *filename, char *target, FILE *f)
{
  bfd *file = bfd_openr (filename, target);
  if (file == NULL)
    fatal (_("fatal error: cannot open file"));

  if (! bfd_check_format (file, bfd_object))
    fatal (_("fatal error: cannot open file"));

  dyninfo (file, f);
  bfd_close (file);
}
int
main (int argc, char **argv)
{
  int c;
  char *target = default_target;
  bfd_boolean seenflag = FALSE;
  (void) target;

  #if defined (HAVE_SETLOCALE)
#if defined (HAVE_LC_MESSAGES)
  setlocale (LC_MESSAGES, "");
#endif
  setlocale (LC_CTYPE, "");
#endif

  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  program_name = *argv;
  xmalloc_set_program_name (program_name);
  bfd_set_error_program_name (program_name);

  START_PROGRESS (program_name, 0);

  if (bfd_init () != BFD_INIT_MAGIC)
    fatal (_("fatal error: libbfd ABI mismatch"));
  set_default_bfd_target ();

  while ((c = getopt_long (argc, argv, "", long_options, (int *) 0)) != EOF)
    {
      switch (c)
	{
	case 0:
	  break;
	default:
	  usage (stderr, 1);
	}
    }

  while (optind < argc)
    {
      do_file (argv[optind++], target, stdout);
      seenflag = TRUE;
    }

  if (show_version)
    print_version ("dyninfo");

  if (!seenflag)
    usage (stderr, 2);

  END_PROGRESS (program_name);

  return exit_status;
}
