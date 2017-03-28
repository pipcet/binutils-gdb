/* ELF support for BFD for the WebAssembly target
   Copyright (C) 2017 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _ELF_WASM32_H
#define _ELF_WASM32_H

#include "elf/reloc-macros.h"

/* Relocation types.  */

START_RELOC_NUMBERS (elf_wasm32_reloc_type)
  RELOC_NUMBER (R_WASM32_NONE,            	   0)
  RELOC_NUMBER (R_WASM32_32,           	  	   1)
  RELOC_NUMBER (R_WASM32_REL32,           	   2)
  RELOC_NUMBER (R_WASM32_REL16,           	   3)
  RELOC_NUMBER (R_WASM32_16,           	           4)
  RELOC_NUMBER (R_WASM32_64,                       5)
  RELOC_NUMBER (R_WASM32_REL64,           	   6)
  RELOC_NUMBER (R_WASM32_LEB128,                   7)
  RELOC_NUMBER (R_WASM32_LEB128_GOT,               8)
  RELOC_NUMBER (R_WASM32_LEB128_PLT,               9)
  RELOC_NUMBER (R_WASM32_PLT_INDEX,               10)
  RELOC_NUMBER (R_WASM32_32_CODE,                 11)
  RELOC_NUMBER (R_WASM32_64_CODE,                 12)
  RELOC_NUMBER (R_WASM32_COPY,                    13)
  RELOC_NUMBER (R_WASM32_LEB128_GOT_CODE,         14)
  RELOC_NUMBER (R_WASM32_8,                  	  15)
  RELOC_NUMBER (R_WASM32_CODE_POINTER,            16)
  RELOC_NUMBER (R_WASM32_INDEX,                   17)
  RELOC_NUMBER (R_WASM32_PLT_SIG,                 18)
END_RELOC_NUMBERS (R_WASM32_max = 18)

#endif /* _ELF_WASM32_H */
