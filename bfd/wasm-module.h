/* BFD back-end for WebAssembly modules.
   Copyright (C) 2017 Free Software Foundation, Inc.

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

#ifndef _WASM_MODULE_H
#define _WASM_MODULE_H

#define WASM_MAGIC    { 0x00, 'a', 's', 'm' }
#define WASM_VERSION  { 0x01, 0x00, 0x00, 0x00}

#define WASM_SECTION(number, name) (".wasm." #name)

#define WASM_SECTION_NAME  WASM_SECTION(0, name)

/* The section to report wasm symbols in. */
#define WASM_SECTION_FUNCTION_INDEX ".space.function_index"

#endif /* _WASM_MODULE_H */
