#include "defs.h"
#include "extension-priv.h"
#include "gdbcmd.h"

#ifdef HAVE_PERL
/* Forward decls, these are defined later.  */
extern struct extension_language_ops perl_extension_ops;
#endif

const struct extension_language_defn extension_language_perl =
{
  EXT_LANG_PERL,
  "perl",
  "Perl",

  ".pl",
  "-gdb.pl",

  perl_control,
#ifdef HAVE_PERL
  NULL,
  &perl_extension_ops,
#else
  NULL,
  NULL,
#endif
};

#ifdef HAVE_PERL

#undef OP_SCOPE
#undef _
#undef OP_NULL
#undef OP_LAST

#define OP_NULL PERL_OP_NULL
#define OP_LAST PERL_OP_LAST
#define OP_SCOPE PERL_OP_SCOPE

#include <EXTERN.h>
#include <perl.h>

static PerlInterpreter *my_perl;
static int perl_initialized = 0;

static void
perl_command (char *arg, int from_tty)
{
  if (arg && *arg)
    {
      SV *sv;
      sv = eval_pv(arg, 0);
      sv = get_sv("@", 0);
      if(SvTRUE(sv)) {
	fprintf(stderr, "%s\n", SvPV_nolen(sv));
      }
    }
}

EXTERN_C void xs_init(pTHX);

static void
gdbpl_finish_initialization (const struct extension_language_defn *extlang)
{
  char **env = { NULL };
  char *args_array[] = { NULL };
  char **args = args_array;
  char *gdb_perldir = concat (gdb_datadir, SLASH_STRING, "perl", NULL);
  char *gdb_init = concat (gdb_perldir, SLASH_STRING, "init.pl", NULL);
  char *gdb_invocation = "1;";
  SV *sv;
  char *argv_array[] = { "gdb", gdb_init, NULL };
  char **argv = argv_array;
  int argc = 2;

  PERL_SYS_INIT3(&argc, &argv, &env);
  my_perl = perl_alloc();
  perl_construct(my_perl);
  perl_parse(my_perl, xs_init, argc, argv, NULL);
  PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
  av_push(get_av("INC", 0), newSVpv(gdb_perldir, 0));
  perl_run(my_perl);
  sv = eval_pv(gdb_invocation, 1);
  if (SvTRUE (sv))
    perl_initialized = 1;

  add_com ("perl", class_obscure, perl_command,
	   "Evaluate a Perl command.\n"
	   );

  add_com_alias ("pl", "perl", class_obscure, 1);
}

static int
gdbpl_initialized (const struct extension_language_defn *extlang)
{
  return perl_initialized;
}

struct extension_language_ops perl_extension_ops =
{
  gdbpl_finish_initialization,
  gdbpl_initialized,

  NULL,
};
#endif
