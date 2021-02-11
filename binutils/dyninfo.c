#include "sysdep.h"
#include "bfd.h"
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

int main (int argc, char **argv)
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

  if (show_version)
    print_version ("dyninfo");

  if (!seenflag)
    usage (stderr, 2);

  END_PROGRESS (program_name);

  return exit_status;
}
