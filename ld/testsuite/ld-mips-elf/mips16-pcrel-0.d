#objdump: -dr --prefix-addresses --show-raw-insn
#name: MIPS16 link PC-relative operations 0
#source: ../../../gas/testsuite/gas/mips/mips16-pcrel-0.s
#as: -EB -32
#ld: -EB -Ttext 0 -e 0

.*: +file format .*mips.*

Disassembly of section \.text:
	\.\.\.
[0-9a-f]+ <[^>]*> 0a00      	la	v0,0+010000 <.*>
[0-9a-f]+ <[^>]*> 6500      	nop
[0-9a-f]+ <[^>]*> b200      	lw	v0,0+010004 <.*>
[0-9a-f]+ <[^>]*> 6500      	nop
[0-9a-f]+ <[^>]*> 0aff      	la	v0,0+010404 <.*>
[0-9a-f]+ <[^>]*> 6500      	nop
[0-9a-f]+ <[^>]*> b2ff      	lw	v0,0+010408 <.*>
[0-9a-f]+ <[^>]*> 6500      	nop
[0-9a-f]+ <[^>]*> f400 0a00 	la	v0,0+010410 <.*>
[0-9a-f]+ <[^>]*> f400 b200 	lw	v0,0+010414 <.*>
[0-9a-f]+ <[^>]*> f7ff 0a1c 	la	v0,0+010014 <.*>
[0-9a-f]+ <[^>]*> f7ff b21c 	lw	v0,0+010018 <.*>
[0-9a-f]+ <[^>]*> f7ef 0a1f 	la	v0,0+01801f <.*>
[0-9a-f]+ <[^>]*> f7ef b21f 	lw	v0,0+018023 <.*>
[0-9a-f]+ <[^>]*> f010 0a00 	la	v0,0+008028 <.*>
[0-9a-f]+ <[^>]*> f010 b200 	lw	v0,0+00802c <.*>
[0-9a-f]+ <[^>]*> f000 6a02 	li	v0,2
[0-9a-f]+ <[^>]*> f400 3240 	sll	v0,16
[0-9a-f]+ <[^>]*> f030 4a10 	addiu	v0,-32720
[0-9a-f]+ <[^>]*> f000 6a02 	li	v0,2
[0-9a-f]+ <[^>]*> f400 3240 	sll	v0,16
[0-9a-f]+ <[^>]*> f030 9a5c 	lw	v0,-32708\(v0\)
[0-9a-f]+ <[^>]*> f000 6a01 	li	v0,1
[0-9a-f]+ <[^>]*> f400 3240 	sll	v0,16
[0-9a-f]+ <[^>]*> f050 4a07 	addiu	v0,-32697
[0-9a-f]+ <[^>]*> f000 6a01 	li	v0,1
[0-9a-f]+ <[^>]*> f400 3240 	sll	v0,16
[0-9a-f]+ <[^>]*> f050 9a53 	lw	v0,-32685\(v0\)
[0-9a-f]+ <[^>]*> 6500      	nop
	\.\.\.
	\.\.\.
