/* Python/gdb header for generic use in gdb

   Copyright (C) 2008-2015 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef GDB_PERL_H
#define GDB_PERL_H

#include "extension.h"

/* This is all that perl exports to gdb.  */
extern const struct extension_language_defn extension_language_perl;

/* A very special function. */
extern char *perl_linespec(void);

#endif /* GDB_PERL_H */
