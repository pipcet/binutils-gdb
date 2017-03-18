if [ -z "${RELOCATING}" ]; then
cat << EOF
SECTIONS
{
}
EOF
else
cat <<EOF
ENTRY(_start)
SECTIONS
{
  . = 8192;
  .interp (INFO) : { *(.interp) }
  . = 16384;
  .wasm.data = .;
  .asmjs.header 16384 :
  {
     LONG(ABSOLUTE(__data_start));
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
     LONG(0);
  }
  .got :
  {
     . = ALIGN(., 16);
     __data_start = .;
     *(.got)
  }
  .got.plt :
  {
    *(.got.plt)
  }
  .data :
  {
     . = ALIGN(., 16);
     *(.data*)
     . = ALIGN(., 16);
     *(.gnu.linkonce.d.*)
     . = ALIGN(., 16);
     *(.tm_clone_table*);
     . = ALIGN(., 16);
     *(__libc_IO_vtables)
     . = ALIGN(., 16);
     *(.rodata*)
     . = ALIGN(., 16);
     *(.jcr*)
     . = ALIGN(., 16);
     *(.gcc_except_table*)
     . = ALIGN(., 16);
     *(.eh_frame*)
     . = ALIGN(., 16);
     __start___libc_atexit = .;
     *(__libc_atexit)
     __stop___libc_atexit = .;
     . = ALIGN(., 16);
     __start___libc_subfreeres = .;
     *(__libc_subfreeres)
     __stop___libc_subfreeres = .;
     . = ALIGN(., 16);
     *(__libc_thread_subfreeres)
     . = ALIGN(., 16);
     *(__libc_freeres_ptrs)
     . = ALIGN(., 16);
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
    KEEP (*(.init_array EXCLUDE_FILE (*crtend.o *crtend?.o) .ctors))
    PROVIDE_HIDDEN (__init_array_end = .);
     . = ALIGN(., 16);
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
    KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
    PROVIDE_HIDDEN (__fini_array_end = .);
     . = ALIGN(., 16);
  }
  .bss :
  {
     *(COMMON)
     *(.dynbss)
     *(.bss* .gnu.linkonce.b.*)
     *(.tbss*)
  }
  .preinit_array     :
  {
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  }
  .ctors          :
  {
    /* gcc uses crtbegin.o to find the start of
       the constructors, so we make sure it is
       first.  Because this is a wildcard, it
       doesn't matter if the user does not
       actually link against crtbegin.o; the
       linker won't look for a file to match a
       wildcard.  The wildcard also means that it
       doesn't matter which directory crtbegin.o
       is in.  */
    KEEP (*crtbegin.o(.ctors))
    KEEP (*crtbegin?.o(.ctors))
    /* We don't want to include the .ctor section from
       the crtend.o file until after the sorted ctors.
       The .ctor section from the crtend file contains the
       end of ctors marker and it must be last */
    KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .ctors))
    KEEP (*(SORT(.ctors.*)))
    KEEP (*(.ctors))
  }
  .dtors          :
  {
    KEEP (*crtbegin.o(.dtors))
    KEEP (*crtbegin?.o(.dtors))
    KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .dtors))
    KEEP (*(SORT(.dtors.*)))
    KEEP (*(.dtors))
  }
  . = ALIGN(., 16);
  .wasm.data_end = .;
  .dynamic :
  {
    *(.dynamic)
  }
  .rela.dyn :
  {
    *(.rela.dyn)
  }
  .dynsym :
  {
    *(.dynsym)
  }
  .dynstr :
  {
    *(.dynstr)
  }
  . = 0;
  .space.function_index 0 (INFO) :
  {
       *(.space.function_index.import);
       *(.space.function_index);
       *(.space.function_index.*);
       .wasm.plt_bias = .;
       *(.space.function_index_.plt);
       .wasm.plt_end = .;
  }
  .space.pc 0 (INFO) :
  {
       *(.space.pc.import);
       *(.space.pc);
       *(.space.pc.*);
       *(.space.pc_.plt);
       .wasm.pc_end = .;
  }
  .space.type 0 (INFO) :
  {
       *(.space.type.import);
       *(.space.type);
       *(.space.type.*);
       *(.space.type_.plt);
  }
  .space.import 0 (INFO) :
  {
       *(.space.import.import);
       *(.space.import);
       *(.space.import.*);
       *(.space.import_.plt);
       .wasm.pc_end = .;
  }
  .space.function 0 (INFO) :
  {
      /* There is no function space for imports */
      *(.space.function);
      *(.space.function.*);
      *(.space.function_.plt);
  }
  .space.table 0 (INFO) :
  {
       *(.space.table.import);
       *(.space.table);
       *(.space.table.*);
       *(.space.table_.plt);
  }
  .space.memory 0 (INFO) :
  {
       *(.space.memory.import);
       *(.space.memory);
       *(.space.memory.*);
       *(.space.memory_.plt);
  }
  .space.global 0 (INFO) :
  {
       *(.space.global.import);
       *(.space.global);
       *(.space.global.*);
       *(.space.global_.plt);
  }
  .space.export 0 (INFO) :
  {
       *(.space.export.import);
       *(.space.export);
       *(.space.export.*);
       *(.space.export_.plt);
  }
  .space.element 0 (INFO) :
  {
       *(.space.element.import);
       *(.space.element);
       *(.space.element.*);
       *(.space.element_.plt);
  }
  .space.code 0 (INFO) :
  {
      /* There is no code space for imports. */
      *(.space.code);
      *(.space.code.*);
      *(.space.code_.plt);
  }
  .space.name.function 0 (INFO) :
  {
       *(.space.name.function.import);
       *(.space.name.function);
       *(.space.name.function.*);
       *(.space.name.function_.plt);
  }
  .space.name.local 0 (INFO) :
  {
       *(.space.name.local.import);
       *(.space.name.local);
       *(.space.name.local.*);
       *(.space.name.local_.plt);
  }
  . = 0xc0000000;
  .wasm.type :
  {
       *(.wasm.type.import);
       *(.wasm.type);
       *(.wasm.type.*);
       *(.wasm.type_.plt);
  }
  .wasm.import :
  {
       *(.wasm.import.import);
       *(.wasm.import);
       *(.wasm.import.*);
       *(.wasm.import_.plt);
  }
  .wasm.function :
  {
       /* There is no function payload for imports */
       *(.wasm.function);
       *(.wasm.function.*);
       *(.wasm.function_.plt);
  }
  .wasm.table :
  {
       *(.wasm.table.import);
       *(.wasm.table);
       *(.wasm.table.*);
       *(.wasm.table_.plt);
  }
  .wasm.memory :
  {
       *(.wasm.memory.import);
       *(.wasm.memory);
       *(.wasm.memory.*);
       *(.wasm.memory_.plt);
  }
  .wasm.global :
  {
       *(.wasm.global.import);
       *(.wasm.global);
       *(.wasm.global.*);
       *(.wasm.global_.plt);
  }
  .wasm.export :
  {
       *(.wasm.export.import);
       *(.wasm.export);
       *(.wasm.export.*);
       *(.wasm.export_.plt);
  }
  .wasm.element :
  {
       *(.wasm.element.import);
       *(.wasm.element);
       *(.wasm.element.*);
       *(.wasm.element_.plt);
  }
  .wasm.code :
  {
      /* There is no code payload for imports */
      *(.wasm.code);
      *(.wasm.code.*);
      *(.wasm.code_.plt);
  }
  .wasm.name.function :
  {
       *(.wasm.name.function.import);
       *(.wasm.name.function);
       *(.wasm.name.function.*);
       *(.wasm.name.function_.plt);
  }
  . = 0x80000000;
  .wasm.name.local :
  {
       *(.wasm.name.local.import);
       *(.wasm.name.local);
       *(.wasm.name.local.*);
       *(.wasm.name.local_.plt);
  }
  .plt :
  {
    *(.plt);
  }
  .rela.plt :
  {
    *(.rela.plt);
  }
  .interp :
  {
    *(.interp)
  }
  .hash : { *(.hash) }
EOF

. $srcdir/scripttempl/DWARF.sc

# This is for testing only. For your WebAssembly module to work, you must
# use the macros in wasm32-macros.s rather than simply specifying .text
cat <<EOF
  .text (INFO) : { *(.text) }
  .init (INFO) : { *(.init) }
  .fini (INFO) : { *(.fini) }
  PROVIDE (_etext = .);
  PROVIDE (etext = .);
  /*   /DISCARD/ : { *(*) } */
}
EOF
fi
