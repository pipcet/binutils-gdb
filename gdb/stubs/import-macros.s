#NO_APP
        .macro .import_old name
        .section .str.lib,"ams",1
        .data
__str_\name:
        .asciz "\name"
        .text
        .global \name
        .pushsection .javascript%S,"a"
    function f_$
        .codetextlabel \name
        (pc,sp) {
        pc = pc|0;
        sp = sp|0;
        var fp = 0;
        var ap = 0;
        var rp = 0;
        var r0 = 0;
        var r1 = 0;
        var r2 = 0;
        var r3 = 0;
        var i0 = 0;
        var i1 = 0;
        var i2 = 0;
        var i3 = 0;
        var f0 = 0.0;
        var f1 = 0.0;
        var f2 = 0.0;
        var f3 = 0.0;
        mainloop:
        while(1) { switch (pc|0) {
        .codetextlabeldeffirst \name
        .codetextlabeldeflast .ends.\name
 default:
        if (pc|0 == 0)
            rp = HEAP32[sp+8>>2]|0;
        else
            rp = HEAP32[sp>>2]|0;
        pc = HEAP32[(rp+0)>>2]|0;
        pc = foreign_resolve($
        .datatextlabel __str_\name
        |0)|0;
        fp = HEAP32[(rp+4)>>2]|0;
        sp = HEAP32[(rp+8)>>2]|0;
        ap = HEAP32[(rp+12)>>2]|0;
        r0 = HEAP32[(rp+16)>>2]|0;
        r1 = HEAP32[(rp+20)>>2]|0;
        r2 = HEAP32[(rp+24)>>2]|0;
        r3 = HEAP32[(rp+28)>>2]|0;
        i0 = HEAP32[(rp+32)>>2]|0;
        i1 = HEAP32[(rp+36)>>2]|0;
        i2 = HEAP32[(rp+40)>>2]|0;
        i3 = HEAP32[(rp+44)>>2]|0;
        f0 = +HEAPF64[(rp+48)>>3];
        f1 = +HEAPF64[(rp+56)>>3];
        f2 = +HEAPF64[(rp+64)>>3];
        f3 = +HEAPF64[(rp+72)>>3];
        rp = fp|0;
        break mainloop;
        }}
        HEAP32[(rp+0)>>2] = (pc<<4);
        HEAP32[(rp+4)>>2] = fp|0;
        HEAP32[(rp+8)>>2] = sp|0;
        HEAP32[(rp+12)>>2] = ap|0;
        HEAP32[(rp+16)>>2] = r0|0;
        HEAP32[(rp+20)>>2] = r1|0;
        HEAP32[(rp+24)>>2] = r2|0;
        HEAP32[(rp+28)>>2] = r3|0;
        HEAP32[(rp+32)>>2] = i0|0;
        HEAP32[(rp+36)>>2] = i1|0;
        HEAP32[(rp+40)>>2] = i2|0;
        HEAP32[(rp+44)>>2] = i3|0;
        HEAPF64[(rp+48)>>3] = +f0;
        HEAPF64[(rp+56)>>3] = +f1;
        HEAPF64[(rp+64)>>3] = +f2;
        HEAPF64[(rp+72)>>3] = +f3;
        return rp|0;}
        .popsection
        .p2align 4+12

        .pushsection .special.export,"a"
        .pushsection .javascript%S,"a"
        .ascii "f_"
        .codetextlabel \name
        .ascii ": f_"
        .codetextlabel \name
        .ascii ",\n"
        .popsection
        .popsection
        .pushsection .special.define,"a"
        .pushsection .javascript%S,"a"
        .ascii "\tdeffun({na"
        .ascii "me: \"f_"
        .codetextlabel \name
        .ascii "\", symbol: \"__wrap_\name\", pc0: "
        .codetextlabel \name
        .ascii ", pc1: "
        .codetextlabel .ends.\name
        .ascii "});\n"
        .popsection
        .popsection
        .endm

        .macro .import name
        .section .str.lib,"ams",1
        .data
__str_\name:
        .asciz "\name"
        .text
        .global \name
        .pushsection .javascript%S,"a"
    function f_$
        .codetextlabel \name
        (pc,sp) {
        pc = pc|0;
        sp = sp|0;

        switch (pc|0) {
        .codetextlabeldeffirst \name
        .codetextlabeldeflast .ends.\name
            break;
        }
        return foreign_extcall(
        .datatextlabel __str_\name
        |0, pc|0, sp|0)|0;
        }
        .popsection
        .p2align 4+12

        .pushsection .special.export,"a"
        .pushsection .javascript%S,"a"
        .ascii "f_"
        .codetextlabel \name
        .ascii ": f_"
        .codetextlabel \name
        .ascii ",\n"
        .popsection
        .popsection
        .pushsection .special.define,"a"
        .pushsection .javascript%S,"a"
        .ascii "\tdeffun({na"
        .ascii "me: \"f_"
        .codetextlabel \name
        .ascii "\", symbol: \"__wrap_\name\", pc0: "
        .codetextlabel \name
        .ascii ", pc1: "
        .codetextlabel .ends.\name
        .ascii "});\n"
        .popsection
        .popsection
        .endm

        .macro .import2_old extname,name
        .section .str.lib,"ams",1
        .data
__str_\name:
        .asciz "\extname"
        .text
        .global \name
        .pushsection .javascript%S,"a"
function f_$
        .codetextlabel \name
    (pc,sp,r0,r1) {
        pc = pc|0;
        sp = sp|0;
        r0 = r0|0;
        r1 = r1|0;
        var r2 = 0;
        var r3 = 0;

        var rp = 0;

        switch (pc|0) {
            .codetextlabeldeffirst \name
            .if 0
            sp = (sp|0)-16|0;
            HEAP32[sp>>2] = $
                .codetextlabel \name\().1
            ;
            HEAP32[sp+4>>2] = HEAP32[sp+20>>2];
            return sp|1;
            .endif
            .codetextlabeldef \name\().1
        .codetextlabeldeflast .ends.\name
        default:
            break;
        }
        rp = foreign_extcall(
        .datatextlabel __str_\name
                |0, pc|0, sp|0)|0;
        return (rp|0)+0|0;
        }
        .popsection
        .p2align 4+8

        .pushsection .special.export,"a"
        .pushsection .javascript%S,"a"
        .ascii "f_"
        .codetextlabel \name
        .ascii ": f_"
        .codetextlabel \name
        .ascii ",\n"
        .popsection
        .popsection
        .pushsection .special.define,"a"
        .pushsection .javascript%S,"a"
        .ascii "\tdeffun({na"
        .ascii "me: \"f_"
        .codetextlabel \name
        .ascii "\", symbol: \"\name\", pc0: "
        .codetextlabel \name
        .ascii ", pc1: "
        .codetextlabel .ends.\name
        .ascii "});\n"
        .popsection
        .popsection
        .endm

        .macro .import3 module, extname, name
        .section .str.lib,"ams",1
        .data
.ifndef __str_\name
__str_\name:
        .asciz "\extname"
.endif
.ifndef __str_\module
__str_\module:
        .asciz "\module"
.endif
        .text
        .global \name
        .pushsection .javascript%S,"a"
function f_$
        .codetextlabel \name
    (pc,sp,r0,r1,rpc,rfp) {
        pc = pc|0;
        sp = sp|0;
        r0 = r0|0;
        r1 = r1|0;
        rpc = rpc|0;
        rfp = rfp|0;
        var fp = 0;
        var rp = 0;
        var a = 0;
        mainloop:
        while(1) {
        switch (pc|0) {
        .codetextlabeldeffirst \name
        .labeldef_debug .LFB0
        .cfi_startproc
        sp = (sp|0)-16|0;
        fp = sp|0;
        rp = fp|1;
        pc = $
        .codetextlabel \name\().0
        >>4;
        break mainloop;
        .codetextlabeldef \name\().0
// 3 "import-macro-c.c" 1
        rp = foreign_extcall(
                .datatextlabel __str_\module
                |0,
                .datatextlabel __str_\name
                |0, pc|0, sp+16|0)|0;
        if (rp & 3) {
            rp = fp|1;
            pc = $
            .codetextlabel \name\().0
            >>4;
            break mainloop;
        } else {
            rp = fp|1;
            pc = $
            .codetextlabel \name\().1
            >>4;
            break mainloop;
        }
        .codetextlabeldef \name\().1
// 0 "" 2
        return fp+16|0;
        .set __asmjs_fallthrough, 0
        .cfi_endproc
        .labeldef_debug .LFE0
        .codetextlabeldeflast .ends.\name
 default:
        rp = sp|0;
        pc = HEAP32[rp+4>>2]>>4;
        sp = HEAP32[rp+8>>2]|0;
        fp = rp|0;
        continue;
        }
        {
        bogotics = (bogotics|0)-1|0;
        a = ((bp_hit)|0) | ((bogotics|0)<0);
        if ((a|0) != 0) {
                if (fp|0) {
                        rp = fp|1;
                        break mainloop;
                }
        }
        }
        }
        if ((rp & 3) == 1) {
        HEAP32[fp+0>>2] = 0x0000000f;
        HEAP32[fp+4>>2] = pc<<4;
        HEAP32[fp+8>>2] = sp|0;
        HEAP32[fp+12>>2] = 16;
        }
        return rp|0;}

        .popsection
        .p2align 4+8

        .pushsection .special.export,"a"
        .pushsection .javascript%S,"a"
        .ascii "f_"
        .codetextlabel \name
        .ascii ": f_"
        .codetextlabel \name
        .ascii ",\n"
        .popsection
        .popsection
        .pushsection .special.define,"a"
        .pushsection .javascript%S,"a"
        .ascii "\tdeffun({na"
        .ascii "me: \"f_"
        .codetextlabel \name
        .ascii "\", symbol: \"\name\", pc0: "
        .codetextlabel \name
        .ascii ", pc1: "
        .codetextlabel .ends.\name
        .ascii "});\n"
        .popsection
        .popsection
        .endm

        .macro .import2 extname, name
        .section .str.lib,"ams",1
        .data
__str_\name:
        .asciz "\extname"
        .text
        .global \name
        .pushsection .javascript%S,"a"
function f_$
        .codetextlabel \name
    (pc,sp,r0,r1,rpc,rfp) {
        pc = pc|0;
        sp = sp|0;
        r0 = r0|0;
        r1 = r1|0;
        rpc = rpc|0;
        rfp = rfp|0;
        var fp = 0;
        var rp = 0;
        var a = 0;
        mainloop:
        while(1) {
        switch (pc|0) {
        .codetextlabeldeffirst \name
        .labeldef_debug .LFB0
        .cfi_startproc
        sp = (sp|0)-16|0;
        fp = sp|0;
        rp = fp|1;
        pc = $
        .codetextlabel \name\().0
        >>4;
        break mainloop;
        .codetextlabeldef \name\().0
// 3 "import-macro-c.c" 1
        rp = foreign_extcall(
        .datatextlabel __str_\name
                |0, pc|0, sp+16|0)|0;
        if (rp & 3) {
            rp = rp|1;
            pc = $
            .codetextlabel \name\().1
            >>4;
            break mainloop;
        } else {
            rp = fp|1;
            pc = $
            .codetextlabel \name\().1
            >>4;
            break mainloop;
        }
        .codetextlabeldef \name\().1
// 0 "" 2
        return fp+16|0;
        .set __asmjs_fallthrough, 0
        .cfi_endproc
        .labeldef_debug .LFE0
        .codetextlabeldeflast .ends.\name
 default:
        rp = sp|0;
        pc = HEAP32[rp+4>>2]>>4;
        sp = HEAP32[rp+8>>2]|0;
        fp = rp|0;
        continue;
        }
        {
        bogotics = (bogotics|0)-1|0;
        a = ((bp_hit)|0) | ((bogotics|0)<0);
        if ((a|0) != 0) {
                if (fp|0) {
                        rp = fp|1;
                        break mainloop;
                }
        }
        }
        }
        if ((rp & 3) == 1) {
        HEAP32[fp+0>>2] = 0x0000000f;
        HEAP32[fp+4>>2] = pc<<4;
        HEAP32[fp+8>>2] = sp|0;
        HEAP32[fp+12>>2] = 16;
        }
        return rp|0;}

        .popsection
        .p2align 4+8

        .pushsection .special.export,"a"
        .pushsection .javascript%S,"a"
        .ascii "f_"
        .codetextlabel \name
        .ascii ": f_"
        .codetextlabel \name
        .ascii ",\n"
        .popsection
        .popsection
        .pushsection .special.define,"a"
        .pushsection .javascript%S,"a"
        .ascii "\tdeffun({na"
        .ascii "me: \"f_"
        .codetextlabel \name
        .ascii "\", symbol: \"\name\", pc0: "
        .codetextlabel \name
        .ascii ", pc1: "
        .codetextlabel .ends.\name
        .ascii "});\n"
        .popsection
        .popsection
        .endm
