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
  . = 16384;
  .wasm.data = .;
  .asmjs.header :
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
  .wasm.chars.function_index 0 (NOLOAD) :
  {
       *(.wasm.chars.function_index.import)
       *(.wasm.chars.function_index.a);
       *(.wasm.chars.function_index.b);
       .wasm.plt_bias = .;
       *(.wasm.chars.function_index.plt)
  }
  .wasm.plt_end = .;
  .wasm.space.pc 0 (NOLOAD) :
  {
       *(.wasm.space.pc)
       .wasm.pc_end = .;
  }
  . = 0x80000000;
  .wasm.chars.name.function (NOLOAD) :
  {
       *(.wasm.chars.name.function)
  }
  .wasm.payload.name.function :
  {
       *(.wasm.payload.name.function)
  }
  .wasm.chars.name.function.plt (NOLOAD) :
  {
       *(.wasm.chars.name.function.plt)
  }
  .wasm.payload.name.function.plt :
  {
       *(.wasm.payload.name.function.plt)
  }
  .wasm.chars.name.local (NOLOAD) :
  {
       *(.wasm.chars.name.local)
  }
  .wasm.payload.name.local :
  {
       *(.wasm.payload.name.local)
  }
  .wasm.chars.code (NOLOAD) :
  {
      *(.wasm.chars.code)
      *(.wasm.chars.code.plt)
  }
  .wasm.payload.code :
  {
      *(.wasm.payload.code)
      *(.wasm.payload.code.plt)
  }
  .wasm.chars.function (NOLOAD) :
  {
      *(.wasm.chars.function)
      *(.wasm.chars.function.plt)
  }
  .wasm.payload.function :
  {
       *(.wasm.payload.function)
       *(.wasm.payload.function.plt)
  }
  .wasm.chars.element 0 (NOLOAD) :
  {
       *(.wasm.chars.element.a)
       *(.wasm.chars.element)
       *(.wasm.chars.element.plt)
  }
  .wasm.payload.element :
  {
       *(.wasm.payload.element.a)
       *(.wasm.payload.element)
       *(.wasm.payload.element.plt)
  }
  .plt :
  {
    *(.plt)
  }
  .dynamic :
  {
    *(.dynamic)
  }
  .interp :
  {
    *(.interp)
  }
  .hash : { *(.hash) }
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
EOF

. $srcdir/scripttempl/DWARF.sc

cat <<EOF
  /DISCARD/ : { *(.text) *(.init) *(.fini) }
}
EOF
fi
