/* WebAssembly assembler/disassembler support.
   Copyright (C) 2017-2020 Free Software Foundation, Inc.

   This file is part of GAS, the GNU assembler.

   GAS is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING3.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

/* WebAssembly opcodes.  Each opcode invokes the WASM_OPCODE macro
   with the following arguments:

   1. Code bytes.
   2. Mnemonic.
   3. Immediate types.
   3. Input type.
   4. Output type.
   5. Opcode class.
*/

#if 0
WASM_OPCODE ({0x00}, "unreachable", {}, {}, {})
WASM_OPCODE ({0x01}, "nop", {}, {}, {})
WASM_OPCODE ({0x02}, "block", {wasm_block_type}, {}, {})
WASM_OPCODE ({0x03}, "loop", {wasm_block_type}, {}, {})
WASM_OPCODE ({0x04}, "if", {wasm_block_type}, {}, {})
WASM_OPCODE ({0x05}, "else", {}, {}, {})
WASM_OPCODE ({0x06}, "try", EXCEPTIONS, {}, {}, {})
WASM_OPCODE ({0x0b}, "end", {}, {}, {})
WASM_OPCODE ({0x0c}, "br", {wasm_block}, {}, {})
WASM_OPCODE ({0x0d}, "br_if", {wasm_block}, {i32}, {})
WASM_OPCODE ({0x0e}, "br_table", {wasm_block_table}, {i32}, {})
WASM_OPCODE ({0x0f}, "return", {}, {args}, {})
WASM_OPCODE ({0x10}, "call", {wasm_function}, {args}, {retv})
WASM_OPCODE ({0x11}, "call_indirect", {}, {args}, {retv})
WASM_OPCODE ({0x12}, "return_call", TAIL_CALL, {wasm_function}, {args}, {})
WASM_OPCODE ({0x13}, "return_call_indirect", TAIL_CALL, {}, {args}, {})
WASM_OPCODE ({0x1a}, "drop", {}, {any}, {})
WASM_OPCODE ({0x1b}, "select", {}, {any,any,any}, {any})
WASM_OPCODE ({0x20}, "local.get", {wasm_local}, {}, any)
WASM_OPCODE ({0x21}, "local.set", {wasm_local}, {}, any)
WASM_OPCODE ({0x22}, "local.tee", {wasm_local}, {}, any)
WASM_OPCODE ({0x23}, "global.get", {wasm_global}, {}, any)
WASM_OPCODE ({0x24}, "global.get", {wasm_global}, {}, any)
WASM_OPCODE ({0x28}, "i32.load", {wasm_memory}, addr, i32)
WASM_OPCODE ({0x29}, "i64.load", {wasm_memory}, addr, i64)
WASM_OPCODE ({0x2a}, "f32.load", {wasm_memory}, addr, i32)
WASM_OPCODE ({0x2b}, "f64.load", {wasm_memory}, addr, f64)
#endif

WASM_OPCODE (0x00, "unreachable", void, void, special, agnostic)
WASM_OPCODE (0x01, "nop", void, void, special, agnostic)
WASM_OPCODE (0x02, "block", void, void, typed, agnostic)
WASM_OPCODE (0x03, "loop", void, void, typed, agnostic)
WASM_OPCODE (0x04, "if", void, void, typed, agnostic)
/* "else": Not listed as an instruction in the WebAssembly spec.  */
WASM_OPCODE (0x05, "else", void, void, special, agnostic)
#define WASM_PROPOSAL_EXCEPTIONS "Exceptions"
#define WASM_PROPOSAL_THREADS "https://github.com/WebAssembly/threads/blob/master/proposals/threads/Overview.md"
#define WASM_PROPOSAL_TAIL_CALL "https://github.com/WebAssembly/tail-call/tree/master/proposals/tail-call"
#define WASM_PROPOSAL_NONTRAPPING_CONVERSIONS "non-trapping conversions"
/* https://github.com/WebAssembly/exception-handling/blob/master/proposals/Exceptions.md */
#define WASM_PROPOSAL_BULK_MEMORY "https://github.com/WebAssembly/bulk-memory-operations/blob/master/proposals/bulk-memory-operations/Overview.md"
WASM_PROPOSED_OPCODE (0x06, EXCEPTIONS,
		      "try", void, void, special, agnostic)
WASM_PROPOSED_OPCODE (0x07, EXCEPTIONS,
		      "catch", void, void, special, agnostic)
WASM_PROPOSED_OPCODE (0x08, EXCEPTIONS,
		      "throw", void, void, special, agnostic)
WASM_PROPOSED_OPCODE (0x09, EXCEPTIONS,
		      "rethrow", void, void, special, agnostic)
WASM_PROPOSED_OPCODE (0x0a, EXCEPTIONS,
		      "br_on_exn", void, void, special, agnostic)
/* "end": Not listed as an instruction in the WebAssembly spec.  */
WASM_OPCODE (0x0b, "end", void, void, special, agnostic)
WASM_OPCODE (0x0c, "br", void, void, break, agnostic)
WASM_OPCODE (0x0d, "br_if", void, void, break_if, agnostic)
WASM_OPCODE (0x0e, "br_table", void, void, break_table, agnostic)
WASM_OPCODE (0x0f, "return", void, void, return, agnostic)

WASM_OPCODE (0x10, "call", any, any, call, agnostic)
WASM_OPCODE (0x11, "call_indirect", any, any, call_indirect, agnostic)

WASM_PROPOSED_OPCODE (0x12, TAIL_CALL,
		      "return_call", any, void, call, agnostic)
WASM_PROPOSED_OPCODE (0x13, TAIL_CALL,
		      "return_call_indirect", any, void, call, agnostic)

WASM_OPCODE (0x1a, "drop", any, any, drop, agnostic)
WASM_OPCODE (0x1b, "select", any, any, select, agnostic)

WASM_OPCODE (0x20, "local.get", any, any, local_get, agnostic)
WASM_OPCODE (0x21, "local.set", any, any, local_set, agnostic)
WASM_OPCODE (0x22, "local.tee", any, any, local_tee, agnostic)
WASM_OPCODE (0x23, "global.get", any, any, local_get, agnostic)
WASM_OPCODE (0x24, "global.set", any, any, local_set, agnostic)

WASM_OPCODE (0x28, "i32.load", i32, i32, load, agnostic)
WASM_OPCODE (0x29, "i64.load", i32, i64, load, agnostic)
WASM_OPCODE (0x2a, "f32.load", i32, f32, load, agnostic)
WASM_OPCODE (0x2b, "f64.load", i32, f64, load, agnostic)
WASM_OPCODE (0x2c, "i32.load8_s", i32, i32, load, signed)
WASM_OPCODE (0x2d, "i32.load8_u", i32, i32, load, unsigned)
WASM_OPCODE (0x2e, "i32.load16_s", i32, i32, load, signed)
WASM_OPCODE (0x2f, "i32.load16_u", i32, i32, load, unsigned)
WASM_OPCODE (0x30, "i64.load8_s", i32, i64, load, signed)
WASM_OPCODE (0x31, "i64.load8_u", i32, i64, load, unsigned)
WASM_OPCODE (0x32, "i64.load16_s", i32, i64, load, signed)
WASM_OPCODE (0x33, "i64.load16_u", i32, i64, load, unsigned)
WASM_OPCODE (0x34, "i64.load32_s", i32, i64, load, signed)
WASM_OPCODE (0x35, "i64.load32_u", i32, i64, load, unsigned)
WASM_OPCODE (0x36, "i32.store", i32, void, store, agnostic)
WASM_OPCODE (0x37, "i64.store", i64, void, store, agnostic)
WASM_OPCODE (0x38, "f32.store", f32, void, store, agnostic)
WASM_OPCODE (0x39, "f64.store", f64, void, store, agnostic)
WASM_OPCODE (0x3a, "i32.store8", i32, void, store, agnostic)
WASM_OPCODE (0x3b, "i32.store16", i32, void, store, agnostic)
WASM_OPCODE (0x3c, "i64.store8", i64, void, store, agnostic)
WASM_OPCODE (0x3d, "i64.store16", i64, void, store, agnostic)
WASM_OPCODE (0x3e, "i64.store32", i64, void, store, agnostic)

/* These might have to become WASM_OPCODE_2 (0x3f, 0x00 ...) etc. at
 * some point.  */
WASM_OPCODE (0x3f, "memory.size", void, i32, current_memory, agnostic)
WASM_OPCODE (0x40, "memory.grow", void, i32, grow_memory, agnostic)

WASM_OPCODE (0x41, "i32.const", i32, i32, i32_const, agnostic)
WASM_OPCODE (0x42, "i64.const", i64, i64, i64_const, agnostic)
WASM_OPCODE (0x43, "f32.const", f32, f32, f32_const, agnostic)
WASM_OPCODE (0x44, "f64.const", f64, f64, f64_const, agnostic)

WASM_OPCODE (0x45, "i32.eqz", i32, i32, eqz, agnostic)
WASM_OPCODE (0x46, "i32.eq", i32, i32, relational, agnostic)
WASM_OPCODE (0x47, "i32.ne", i32, i32, relational, agnostic)
WASM_OPCODE (0x48, "i32.lt_s", i32, i32, relational, signed)
WASM_OPCODE (0x49, "i32.lt_u", i32, i32, relational, unsigned)
WASM_OPCODE (0x4a, "i32.gt_s", i32, i32, relational, signed)
WASM_OPCODE (0x4b, "i32.gt_u", i32, i32, relational, unsigned)
WASM_OPCODE (0x4c, "i32.le_s", i32, i32, relational, signed)
WASM_OPCODE (0x4d, "i32.le_u", i32, i32, relational, unsigned)
WASM_OPCODE (0x4e, "i32.ge_s", i32, i32, relational, signed)
WASM_OPCODE (0x4f, "i32.ge_u", i32, i32, relational, unsigned)

WASM_OPCODE (0x50, "i64.eqz", i64, i32, eqz, agnostic)
WASM_OPCODE (0x51, "i64.eq", i64, i32, relational, agnostic)
WASM_OPCODE (0x52, "i64.ne", i64, i32, relational, agnostic)
WASM_OPCODE (0x53, "i64.lt_s", i64, i32, relational, signed)
WASM_OPCODE (0x54, "i64.lt_u", i64, i32, relational, unsigned)
WASM_OPCODE (0x55, "i64.gt_s", i64, i32, relational, signed)
WASM_OPCODE (0x56, "i64.gt_u", i64, i32, relational, unsigned)
WASM_OPCODE (0x57, "i64.le_s", i64, i32, relational, signed)
WASM_OPCODE (0x58, "i64.le_u", i64, i32, relational, unsigned)
WASM_OPCODE (0x59, "i64.ge_s", i64, i32, relational, signed)
WASM_OPCODE (0x5a, "i64.ge_u", i64, i32, relational, unsigned)

WASM_OPCODE (0x5b, "f32.eq", f32, i32, relational, floating)
WASM_OPCODE (0x5c, "f32.ne", f32, i32, relational, floating)
WASM_OPCODE (0x5d, "f32.lt", f32, i32, relational, floating)
WASM_OPCODE (0x5e, "f32.gt", f32, i32, relational, floating)
WASM_OPCODE (0x5f, "f32.le", f32, i32, relational, floating)
WASM_OPCODE (0x60, "f32.ge", f32, i32, relational, floating)

WASM_OPCODE (0x61, "f64.eq", f64, i32, relational, floating)
WASM_OPCODE (0x62, "f64.ne", f64, i32, relational, floating)
WASM_OPCODE (0x63, "f64.lt", f64, i32, relational, floating)
WASM_OPCODE (0x64, "f64.gt", f64, i32, relational, floating)
WASM_OPCODE (0x65, "f64.le", f64, i32, relational, floating)
WASM_OPCODE (0x66, "f64.ge", f64, i32, relational, floating)

WASM_OPCODE (0x67, "i32.clz", i32, i32, unary, agnostic)
WASM_OPCODE (0x68, "i32.ctz", i32, i32, unary, agnostic)
WASM_OPCODE (0x69, "i32.popcnt", i32, i32, unary, agnostic)

WASM_OPCODE (0x6a, "i32.add", i32, i32, binary, agnostic)
WASM_OPCODE (0x6b, "i32.sub", i32, i32, binary, agnostic)
WASM_OPCODE (0x6c, "i32.mul", i32, i32, binary, agnostic)
WASM_OPCODE (0x6d, "i32.div_s", i32, i32, binary, signed)
WASM_OPCODE (0x6e, "i32.div_u", i32, i32, binary, unsigned)
WASM_OPCODE (0x6f, "i32.rem_s", i32, i32, binary, signed)
WASM_OPCODE (0x70, "i32.rem_u", i32, i32, binary, unsigned)
WASM_OPCODE (0x71, "i32.and", i32, i32, binary, agnostic)
WASM_OPCODE (0x72, "i32.or", i32, i32, binary, agnostic)
WASM_OPCODE (0x73, "i32.xor", i32, i32, binary, agnostic)
WASM_OPCODE (0x74, "i32.shl", i32, i32, binary, agnostic)
WASM_OPCODE (0x75, "i32.shr_s", i32, i32, binary, signed)
WASM_OPCODE (0x76, "i32.shr_u", i32, i32, binary, unsigned)
WASM_OPCODE (0x77, "i32.rotl", i32, i32, binary, agnostic)
WASM_OPCODE (0x78, "i32.rotr", i32, i32, binary, agnostic)

WASM_OPCODE (0x79, "i64.clz", i64, i64, unary, agnostic)
WASM_OPCODE (0x7a, "i64.ctz", i64, i64, unary, agnostic)
WASM_OPCODE (0x7b, "i64.popcnt", i64, i64, unary, agnostic)

WASM_OPCODE (0x7c, "i64.add", i64, i64, binary, agnostic)
WASM_OPCODE (0x7d, "i64.sub", i64, i64, binary, agnostic)
WASM_OPCODE (0x7e, "i64.mul", i64, i64, binary, agnostic)
WASM_OPCODE (0x7f, "i64.div_s", i64, i64, binary, signed)
WASM_OPCODE (0x80, "i64.div_u", i64, i64, binary, unsigned)
WASM_OPCODE (0x81, "i64.rem_s", i64, i64, binary, signed)
WASM_OPCODE (0x82, "i64.rem_u", i64, i64, binary, unsigned)
WASM_OPCODE (0x83, "i64.and", i64, i64, binary, agnostic)
WASM_OPCODE (0x84, "i64.or", i64, i64, binary, agnostic)
WASM_OPCODE (0x85, "i64.xor", i64, i64, binary, agnostic)
WASM_OPCODE (0x86, "i64.shl", i64, i64, binary, agnostic)
WASM_OPCODE (0x87, "i64.shr_s", i64, i64, binary, signed)
WASM_OPCODE (0x88, "i64.shr_u", i64, i64, binary, unsigned)
WASM_OPCODE (0x89, "i64.rotl", i64, i64, binary, agnostic)
WASM_OPCODE (0x8a, "i64.rotr", i64, i64, binary, agnostic)

WASM_OPCODE (0x8b, "f32.abs", f32, f32, unary, floating)
WASM_OPCODE (0x8c, "f32.neg", f32, f32, unary, floating)
WASM_OPCODE (0x8d, "f32.ceil", f32, f32, unary, floating)
WASM_OPCODE (0x8e, "f32.floor", f32, f32, unary, floating)
WASM_OPCODE (0x8f, "f32.trunc", f32, f32, unary, floating)
WASM_OPCODE (0x90, "f32.nearest", f32, f32, unary, floating)
WASM_OPCODE (0x91, "f32.sqrt", f32, f32, unary, floating)
WASM_OPCODE (0x92, "f32.add", f32, f32, binary, floating)
WASM_OPCODE (0x93, "f32.sub", f32, f32, binary, floating)
WASM_OPCODE (0x94, "f32.mul", f32, f32, binary, floating)
WASM_OPCODE (0x95, "f32.div", f32, f32, binary, floating)
WASM_OPCODE (0x96, "f32.min", f32, f32, binary, floating)
WASM_OPCODE (0x97, "f32.max", f32, f32, binary, floating)
WASM_OPCODE (0x98, "f32.copysign", f32, f32, binary, floating)

WASM_OPCODE (0x99, "f64.abs", f64, f64, unary, floating)
WASM_OPCODE (0x9a, "f64.neg", f64, f64, unary, floating)
WASM_OPCODE (0x9b, "f64.ceil", f64, f64, unary, floating)
WASM_OPCODE (0x9c, "f64.floor", f64, f64, unary, floating)
WASM_OPCODE (0x9d, "f64.trunc", f64, f64, unary, floating)
WASM_OPCODE (0x9e, "f64.nearest", f64, f64, unary, floating)
WASM_OPCODE (0x9f, "f64.sqrt", f64, f64, unary, floating)
WASM_OPCODE (0xa0, "f64.add", f64, f64, binary, floating)
WASM_OPCODE (0xa1, "f64.sub", f64, f64, binary, floating)
WASM_OPCODE (0xa2, "f64.mul", f64, f64, binary, floating)
WASM_OPCODE (0xa3, "f64.div", f64, f64, binary, floating)
WASM_OPCODE (0xa4, "f64.min", f64, f64, binary, floating)
WASM_OPCODE (0xa5, "f64.max", f64, f64, binary, floating)
WASM_OPCODE (0xa6, "f64.copysign", f64, f64, binary, floating)

WASM_OPCODE (0xa7, "i32.wrap_i64", i64, i32, conv, agnostic)
WASM_OPCODE (0xa8, "i32.trunc_f32_s", f32, i32, conv, signed)
WASM_OPCODE (0xa9, "i32.trunc_f32_u", f32, i32, conv, unsigned)
WASM_OPCODE (0xaa, "i32.trunc_f64_s", f64, i32, conv, signed)
WASM_OPCODE (0xab, "i32.trunc_f64_u", f64, i32, conv, unsigned)
WASM_OPCODE (0xac, "i64.extend_i32_s", i32, i64, conv, signed)
WASM_OPCODE (0xad, "i64.extend_i32_u", i32, i64, conv, unsigned)
WASM_OPCODE (0xae, "i64.trunc_f32_s", f32, i64, conv, signed)
WASM_OPCODE (0xaf, "i64.trunc_f32_u", f32, i64, conv, unsigned)
WASM_OPCODE (0xb0, "i64.trunc_f64_s", f64, i64, conv, signed)
WASM_OPCODE (0xb1, "i64.trunc_f64_u", f64, i64, conv, unsigned)

WASM_OPCODE (0xb2, "f32.convert_i32_s", i32, f32, conv, signed)
WASM_OPCODE (0xb3, "f32.convert_i32_u", i32, f32, conv, unsigned)
WASM_OPCODE (0xb4, "f32.convert_i64_s", i64, f32, conv, signed)
WASM_OPCODE (0xb5, "f32.convert_i64_u", i64, f32, conv, unsigned)
WASM_OPCODE (0xb6, "f32.demote_f64", f64, f32, conv, floating)
WASM_OPCODE (0xb7, "f64.convert_i32_s", i32, f64, conv, signed)
WASM_OPCODE (0xb8, "f64.convert_i32_u", i32, f64, conv, unsigned)
WASM_OPCODE (0xb9, "f64.convert_i64_s", i64, f64, conv, signed)
WASM_OPCODE (0xba, "f64.convert_i64_u", i64, f64, conv, unsigned)
WASM_OPCODE (0xbb, "f64.promote_f32", f32, f64, conv, floating)

WASM_OPCODE (0xbc, "i32.reinterpret_f32", f32, i32, conv, agnostic)
WASM_OPCODE (0xbd, "i64.reinterpret_f64", f64, i64, conv, agnostic)
WASM_OPCODE (0xbe, "f32.reinterpret_i32", i32, f32, conv, agnostic)
WASM_OPCODE (0xbf, "f64.reinterpret_i64", i64, f64, conv, agnostic)

/* The following are listed in the spec, but also listed as proposed on
 * https://github.com/WebAssembly/sign-extension-ops/blob/master/proposals/sign-extension-ops/Overview.md */
WASM_OPCODE (0xc0, "i32.extend8_s", i32, i32, conv, signed)
WASM_OPCODE (0xc1, "i32.extend16_s", i32, i32, conv, signed)
WASM_OPCODE (0xc2, "i64.extend8_s", i64, i64, conv, signed)
WASM_OPCODE (0xc3, "i64.extend16_s", i64, i64, conv, signed)
WASM_OPCODE (0xc4, "i64.extend32_s", i64, i64, conv, signed)

WASM_OPCODE (0xfc, "escape_fc", void, void, escape, agnostic)

/* The following are listed in the spec, but also listed as proposed on
 *  */
WASM_OPCODE_2 (0xfc, 0x00, "i32.trunc_sat_f32_s", f32, i32, conv, signed)
WASM_OPCODE_2 (0xfc, 0x01, "i32.trunc_sat_f32_u", f32, i32, conv, unsigned)
WASM_OPCODE_2 (0xfc, 0x02, "i32.trunc_sat_f64_s", f64, i32, conv, signed)
WASM_OPCODE_2 (0xfc, 0x03, "i32.trunc_sat_f64_u", f64, i32, conv, unsigned)
WASM_OPCODE_2 (0xfc, 0x04, "i64.trunc_sat_f32_s", f32, i64, conv, signed)
WASM_PROPOSED_OPCODE_2 (0xfc, 0x08, BULK_MEMORY,
			"memory.init", void, void, memory, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfc, 0x09, BULK_MEMORY,
			"data.drop", void, void, memory, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfc, 0x0a, BULK_MEMORY,
			"memory.copy", void, void, memory, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfc, 0x0b, BULK_MEMORY,
			"memory.fill", void, void, memory, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfc, 0x0c, BULK_MEMORY,
			"table.init", void, void, memory, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfc, 0x0d, BULK_MEMORY,
			"elem.drop", void, void, memory, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfc, 0x0e, BULK_MEMORY,
			"table.copy", void, void, memory, agnostic)
WASM_OPCODE_2 (0xfc, 0x05, "i64.trunc_sat_f32_u", f32, i64, conv, unsigned)
WASM_OPCODE_2 (0xfc, 0x06, "i64.trunc_sat_f64_s", f64, i64, conv, signed)
WASM_OPCODE_2 (0xfc, 0x07, "i64.trunc_sat_f64_u", f64, i64, conv, unsigned)

WASM_PROPOSED_OPCODE (0xfe, THREADS,
		      "escape_fe", void, void, escape, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x00, THREADS,
			"memory.atomic.notify", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x01, THREADS,
			"memory.atomic.notify", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x02, THREADS,
			"memory.atomic.notify", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x03, THREADS,
			"escape_fe03", void, void, escape, agnostic,)
WASM_PROPOSED_OPCODE_3 (0xfe, 0x03, 0x00, THREADS,
			"memory.atomic.notify", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x10, THREADS,
			"i32.atomic.load", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x11, THREADS,
			"i64.atomic.load", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x12, THREADS,
			"i32.atomic.load8_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x13, THREADS,
			"i32.atomic.load16_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x14, THREADS,
			"i64.atomic.load8_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x15, THREADS,
			"i64.atomic.load16_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x16, THREADS,
			"i64.atomic.load32_u", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x17, THREADS,
			"i32.atomic.store", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x18, THREADS,
			"i64.atomic.store", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x19, THREADS,
			"i32.atomic.store8", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x19, THREADS,
			"i32.atomic.store16", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x1b, THREADS,
			"i64.atomic.store8", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x1c, THREADS,
			"i64.atomic.store16", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x1d, THREADS,
			"i64.atomic.store32", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x1e, THREADS,
			"i32.atomic.rmw.add", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x1f, THREADS,
			"i64.atomic.rmw.add", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x20, THREADS,
			"i32.atomic.rmw8.add_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x21, THREADS,
			"i32.atomic.rmw16.add_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x22, THREADS,
			"i64.atomic.rmw8.add_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x23, THREADS,
			"i64.atomic.rmw16.add_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x24, THREADS,
			"i64.atomic.rmw32.add_u", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x25, THREADS,
			"i32.atomic.rmw.sub", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x26, THREADS,
			"i64.atomic.rmw.sub", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x27, THREADS,
			"i32.atomic.rmw8.sub_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x28, THREADS,
			"i32.atomic.rmw16.sub_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x29, THREADS,
			"i64.atomic.rmw8.sub_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x2a, THREADS,
			"i64.atomic.rmw16.sub_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x2b, THREADS,
			"i64.atomic.rmw32.sub_u", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x2c, THREADS,
			"i32.atomic.rmw.and", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x2d, THREADS,
			"i64.atomic.rmw.and", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x2e, THREADS,
			"i32.atomic.rmw8.and_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x2f, THREADS,
			"i32.atomic.rmw16.and_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x30, THREADS,
			"i64.atomic.rmw8.and_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x31, THREADS,
			"i64.atomic.rmw16.and_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x32, THREADS,
			"i64.atomic.rmw32.and_u", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x33, THREADS,
			"i32.atomic.rmw.or", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x34, THREADS,
			"i64.atomic.rmw.or", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x35, THREADS,
			"i32.atomic.rmw8.or_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x36, THREADS,
			"i32.atomic.rmw16.or_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x37, THREADS,
			"i64.atomic.rmw8.or_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x38, THREADS,
			"i64.atomic.rmw16.or_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x39, THREADS,
			"i64.atomic.rmw32.or_u", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x3a, THREADS,
			"i32.atomic.rmw.xor", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x3b, THREADS,
			"i64.atomic.rmw.xor", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x3c, THREADS,
			"i32.atomic.rmw8.xor_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x3d, THREADS,
			"i32.atomic.rmw16.xor_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x3e, THREADS,
			"i64.atomic.rmw8.xor_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x3f, THREADS,
			"i64.atomic.rmw16.xor_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x40, THREADS,
			"i64.atomic.rmw32.xor_u", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x41, THREADS,
			"i32.atomic.rmw.xchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x42, THREADS,
			"i64.atomic.rmw.xchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x43, THREADS,
			"i32.atomic.rmw8.xchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x44, THREADS,
			"i32.atomic.rmw16.xchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x45, THREADS,
			"i64.atomic.rmw8.xchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x46, THREADS,
			"i64.atomic.rmw16.xchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x47, THREADS,
			"i64.atomic.rmw32.xchg_u", access, agnostic)

WASM_PROPOSED_OPCODE_2 (0xfe, 0x48, THREADS,
			"i32.atomic.rmw.cmpxchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x49, THREADS,
			"i64.atomic.rmw.cmpxchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x4a, THREADS,
			"i32.atomic.rmw8.cmpxchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x4b, THREADS,
			"i32.atomic.rmw16.cmpxchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x4c, THREADS,
			"i64.atomic.rmw8.cmpxchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x4d, THREADS,
			"i64.atomic.rmw16.cmpxchg_u", access, agnostic)
WASM_PROPOSED_OPCODE_2 (0xfe, 0x4e, THREADS,
			"i64.atomic.rmw32.cmpxchg_u", access, agnostic)

/* This isn't, strictly speaking, an opcode, but is treated as such by
   the assembler.  XXX is this still true?  */
WASM_OPCODE (0x60, "signature", void, void, signature, agnostic)
