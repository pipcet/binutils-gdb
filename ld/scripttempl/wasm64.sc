cat <<EOF
ENTRY(_start)
SECTIONS
{
  . = 16384;
  .asmjs.header :
  {
     LONG(ABSOLUTE(__data_start));
     LONG(0);
     LONG(ABSOLUTE(__terminator));
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
  .data :
  {
     . = ALIGN(., 16);
     __data_start = .;
     *(.data*)
     . = ALIGN(., 16);
     *(.gnu.linkonce.d.*)
     . = ALIGN(., 16);
     *(.rodata*)
     . = ALIGN(., 16);
     *(.jcr*)
     . = ALIGN(., 16);
     *(.dynbss)
     . = ALIGN(., 16);
     *(.bss* .gnu.linkonce.b.*)
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
  .asmjs.term :
  {
    PROVIDE_HIDDEN(__terminator = .);
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
    LONG(0);
  }
  . = 0x4000000000010000;
  .init : { *(.init*) }
  .text :
  {
    *(.text*)
    *(__libc_freeres_fn*)
    *(__libc_thread_freeres_fn*)
  }
  .fini : { *(.fini*) }
  . = 0xc0000000;
  .javascript.init : { FILL(0x20202020); *(.javascript.init*) }
  .javascript.text :
  {
    FILL(0x20202020);
    *(.javascript.text*)
    *(.javascript__libc_freeres_fn*)
    *(.javascript__libc_thread_freeres_fn*)
  }
  .javascript.fini : { FILL(0x20202020); *(.javascript.fini*) }

  .javascript.special.export : { *(.javascript.special.export*) }
  .javascript.special.define : { *(.javascript.special.define*) }
  .javascript.special.fpswitch : { *(.javascript.special.fpswitch*) }

  .wasm_pwas.init : { FILL(0x20202020); *(.wasm_pwas.init*) }
  .wasm_pwas.text :
  {
    FILL(0x20202020);
    *(.wasm_pwas.text*)
    *(.wasm_pwas__libc_freeres_fn*)
    *(.wasm_pwas__libc_thread_freeres_fn*)
  }
  .wasm_pwas.fini : { FILL(0x20202020); *(.wasm_pwas.fini*) }

  .wasm_pwas.special.export : { *(.wasm_pwas.special.export*) }
  .wasm_pwas.special.define : { *(.wasm_pwas.special.define*) }
  .wasm_pwas.special.fpswitch : { *(.wasm_pwas.special.fpswitch*) }
EOF

. $srcdir/scripttempl/DWARF.sc

cat <<EOF
/*  /DISCARD/ : { *(*) } */
}
EOF