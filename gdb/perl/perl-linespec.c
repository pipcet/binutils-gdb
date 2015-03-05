/*
 * The purpose of this file is to pull in as many header files as
 * possible, so gdb will have access to all of its macro definitions
 * from the scope of perl_linespec().
 */

#include "defs.h"
#include "extension-priv.h"
#include "perl.h"
#include "defs.h"
#include "arch-utils.h"
#include "command.h"
#include "ui-out.h"
#include "cli/cli-script.h"
#include "gdbcmd.h"
#include "progspace.h"
#include "objfiles.h"
#include "value.h"
#include "language.h"
#include "event-loop.h"
#include "serial.h"
#include "readline/tilde.h"
#include "extension-priv.h"
#include "cli/cli-utils.h"
#include <ctype.h>
#include <stdio.h>

#define PERL_LINESPEC(file,line) #file ":" #line

char *perl_linespec(void)
{
  static char perl_linespec[] = PERL_LINESPEC(__FILE__, __LINE__);
  return perl_linespec;
}
