if [ -z "${RELOCATING}" ]; then
cat << EOF
SECTIONS
{
}
EOF
else
cat <<EOF
ENTRY(_start)
STARTUP(wasm32-headers.o)
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
     LONG(ABSOLUTE(__preinit_array_start));
     LONG(0);
     LONG(ABSOLUTE(__preinit_array_end));
     LONG(0);
     LONG(ABSOLUTE(__init_array_start));
     LONG(0);
     LONG(ABSOLUTE(__init_array_end));
     LONG(0);
     LONG(ABSOLUTE(__fini_array_start));
     LONG(0);
     LONG(ABSOLUTE(__fini_array_end));
     LONG(0);
  }
  .got :
  {
    . = ALIGN(., 16);
    __data_start = .;
    *(.got)
    . = ALIGN(., 16);
  }
  .got.plt :
  {
    . = ALIGN(., 16);
    *(.got.plt)
    . = ALIGN(., 16);
  }
  .data :
  {
    . = ALIGN(., 16);
    *(.data*);
    . = ALIGN(., 16);
    *(.gnu.linkonce.d.*);
    . = ALIGN(., 16);
    *(.tm_clone_table*);
    . = ALIGN(., 16);
    PROVIDE(__start___libc_IO_vtables = .);
    *(__libc_IO_vtables)
    PROVIDE(__stop___libc_IO_vtables = .);
    . = ALIGN(., 16);
    *(.rodata*);
    . = ALIGN(., 16);
    *(.jcr*);
    . = ALIGN(., 16);
    KEEP(*(.gcc_except_table*));
    . = ALIGN(., 16);
    KEEP(*(.eh_frame*));
    . = ALIGN(., 16);
    __start___libc_atexit = .;
    KEEP(*(__libc_atexit));
    __stop___libc_atexit = .;
    . = ALIGN(., 16);
    __start___libc_subfreeres = .;
    *(__libc_subfreeres);
    __stop___libc_subfreeres = .;
    . = ALIGN(., 16);
    PROVIDE(__start___libc_thread_subfreeres = .);
    *(__libc_thread_subfreeres);
    PROVIDE(__stop___libc_thread_subfreeres = .);
    . = ALIGN(., 16);
    PROVIDE(__start___libc_freeres_ptrs = .);
    *(__libc_freeres_ptrs);
    PROVIDE(__stop___libc_freeres_ptrs = .);
    . = ALIGN(., 16);
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)));
    KEEP (*(.init_array EXCLUDE_FILE (*crtend.o *crtend?.o) .ctors));
    PROVIDE_HIDDEN (__init_array_end = .);
    . = ALIGN(., 16);
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)));
    KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors));
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
    KEEP(*(.space.function_index.import_.null));
    *(.space.function_index.import);
    *(.space.function_index.*);
    *(.space.function_index);
    .wasm.plt_bias = .;
    *(.space.function_index_.plt);
    *(.space.function_index_.pplt);
    .wasm.plt_end = .;
  }
  .space.pc 0 (INFO) :
  {
    KEEP(*(.space.pc.import));
    KEEP(*(.space.pc));
    KEEP(*(.space.pc.*));
    KEEP(*(.space.pc_.plt));
    KEEP(*(.space.pc_.pplt));
    .wasm.pc_end = .;
  }
  .space.global_index 0 (INFO) :
  {
    KEEP(*(.space.global_index.import));
    KEEP(*(.space.global_index));
    KEEP(*(.space.global_index.*));
  }
  .space.type 0 (INFO) :
  {
    *(.space.type.import);
    *(.space.type);
    *(.space.type.*);
    *(.space.type_.plt);
    *(.space.type_.pplt);
  }
  .space.import 0 (INFO) :
  {
    KEEP(*(.space.import_.null));
    KEEP(*(.space.import.import));
    KEEP(*(.space.import));
    KEEP(*(.space.import.*));
    KEEP(*(.space.import_.plt));
    KEEP(*(.space.import_.pplt));
    .wasm.import_end = .;
  }
  .space.function 0 (INFO) :
  {
    /* There is no function space for imports */
    KEEP(*(.space.function.*));
    KEEP(*(.space.function*));
    KEEP(*(.space.function_.plt));
    KEEP(*(.space.function_.pplt));
  }
  .space.table 0 (INFO) :
  {
    KEEP(*(.space.table.import));
    KEEP(*(.space.table));
    KEEP(*(.space.table.*));
    KEEP(*(.space.table_.plt));
    KEEP(*(.space.table_.pplt));
  }
  .space.memory 0 (INFO) :
  {
    KEEP(*(.space.memory.import));
    KEEP(*(.space.memory));
    KEEP(*(.space.memory.*));
    KEEP(*(.space.memory_.plt));
    KEEP(*(.space.memory_.pplt));
  }
  .space.global 0 (INFO) :
  {
    KEEP(*(.space.global.import));
    KEEP(*(.space.global));
    KEEP(*(.space.global.*));
    KEEP(*(.space.global_.plt));
    KEEP(*(.space.global_.pplt));
  }
  .space.export 0 (INFO) :
  {
    KEEP(*(.space.export.import));
    KEEP(*(.space.export));
    KEEP(*(.space.export.*));
    KEEP(*(.space.export_.plt));
    KEEP(*(.space.export_.pplt));
  }
  .space.element 0 (INFO) :
  {
    KEEP(*(.space.element.import_.null))
    *(.space.element.import);
    *(.space.element);
    *(.space.element.*);
    *(.space.element_.plt);
    *(.space.element_.pplt);
  }
  .space.code 0 (INFO) :
  {
    /* There is no code space for imports. */
    *(.space.code);
    *(.space.code.*);
    *(.space.code_.plt);
    *(.space.code_.pplt);
  }
  .space.name.function 0 (INFO) :
  {
    KEEP(*(.space.name.function.import_.null));
    *(.space.name.function.import);
    *(.space.name.function.*);
    *(.space.name.function*);
    *(.space.name.function_.plt);
    *(.space.name.function_.pplt);
  }
  .space.name.local 0 (INFO) :
  {
    *(.space.name.local.import);
    *(.space.name.local);
    *(.space.name.local.*);
    *(.space.name.local_.plt);
    *(.space.name.local_.pplt);
  }
  . = 0xc0000000;
  .wasm.type :
  {
    *(.wasm.type.import);
    *(.wasm.type);
    *(.wasm.type.*);
    *(.wasm.type_.plt);
    *(.wasm.type_.pplt);
  }
  .wasm.import :
  {
    KEEP(*(.wasm.import_.null));
    KEEP(*(.wasm.import.import));
    KEEP(*(.wasm.import));
    KEEP(*(.wasm.import.*));
    KEEP(*(.wasm.import_.plt));
    KEEP(*(.wasm.import_.pplt));
  }
  .wasm.function :
  {
    /* There is no function payload for imports */
    *(.wasm.function);
    *(.wasm.function.*);
    *(.wasm.function_.plt);
    *(.wasm.function_.pplt);
  }
  .wasm.table :
  {
    KEEP(*(.wasm.table.import));
    KEEP(*(.wasm.table));
    KEEP(*(.wasm.table.*));
    KEEP(*(.wasm.table_.plt));
    KEEP(*(.wasm.table_.pplt));
  }
  .wasm.memory :
  {
    KEEP(*(.wasm.memory.import));
    KEEP(*(.wasm.memory));
    KEEP(*(.wasm.memory.*));
    KEEP(*(.wasm.memory_.plt));
    KEEP(*(.wasm.memory_.pplt));
  }
  .wasm.global :
  {
    KEEP(*(.wasm.global.import));
    KEEP(*(.wasm.global));
    KEEP(*(.wasm.global.*));
    KEEP(*(.wasm.global_.plt));
    KEEP(*(.wasm.global_.pplt));
  }
 .wasm.export :
  {
    KEEP(*(.wasm.export.import));
    KEEP(*(.wasm.export));
    KEEP(*(.wasm.export.*));
    KEEP(*(.wasm.export_.plt));
    KEEP(*(.wasm.export_.pplt));
  }
  .wasm.element :
  {
    KEEP(*(.wasm.element.import_.null));
    *(.wasm.element.import);
    *(.wasm.element);
    *(.wasm.element.*);
    *(.wasm.element_.plt);
    *(.wasm.element_.pplt);
  }
  .wasm.code :
  {
    /* There is no code payload for imports */
    *(.wasm.code);
    *(.wasm.code.*);
    *(.wasm.code_.plt);
    *(.wasm.code_.pplt);
  }
  .wasm.name.function :
  {
    KEEP(*(.wasm.name.function.import_.null));
    *(.wasm.name.function.import);
    *(.wasm.name.function.*);
    *(.wasm.name.function*);
    *(.wasm.name.function_.plt);
    *(.wasm.name.function_.pplt);
  }
  . = 0x80000000;
  .wasm.name.local :
  {
    *(.wasm.name.local.import);
    *(.wasm.name.local);
    *(.wasm.name.local.*);
    *(.wasm.name.local_.plt);
    *(.wasm.name.local_.pplt);
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
    *(.interp);
  }
  /* The next line must be on a single line, because glibc performs sed
   * manipulation on this linker script. */
  .hash (INFO) : { *(.hash); }
  .gnu.hash (INFO) : { *(.gnu.hash); }
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
