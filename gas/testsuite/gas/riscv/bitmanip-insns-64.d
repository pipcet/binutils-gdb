#as: -march=rv64i_zba_zbb_zbc -defsym __64_bit__=1
#source: bitmanip-insns.s
#objdump: -dr -Mno-aliases

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <.text>:
[ 	]+[0-9a-f]+:[ 	]+0805c53b[ 	]+zext.h[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+6b85d513[ 	]+rev8[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+2875d513[ 	]+orc.b[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+0805853b[ 	]+add.uw[ 	]+a0,a1,zero
[ 	]+[0-9a-f]+:[ 	]+20c5a533[ 	]+sh1add[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+20c5c533[ 	]+sh2add[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+20c5e533[ 	]+sh3add[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+20c5a53b[ 	]+sh1add.uw[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+20c5c53b[ 	]+sh2add.uw[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+20c5e53b[ 	]+sh3add.uw[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+08c5853b[ 	]+add.uw[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0805951b[ 	]+slli.uw[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+0bf5951b[ 	]+slli.uw[ 	]+a0,a1,0x3f
[ 	]+[0-9a-f]+:[ 	]+60059513[ 	]+clz[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+60159513[ 	]+ctz[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+60259513[ 	]+cpop[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+0ac5c533[ 	]+min[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ac5e533[ 	]+max[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ac5d533[ 	]+minu[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ac5f533[ 	]+maxu[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+60459513[ 	]+sext.b[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+60559513[ 	]+sext.h[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+40c5f533[ 	]+andn[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+40c5e533[ 	]+orn[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+00c5c533[ 	]+xor[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+6005d513[ 	]+rori[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+61f5d513[ 	]+rori[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+60c5d533[ 	]+ror[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+6005d513[ 	]+rori[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+61f5d513[ 	]+rori[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+60c59533[ 	]+rol[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+6005951b[ 	]+clzw[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+6015951b[ 	]+ctzw[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+6025951b[ 	]+cpopw[ 	]+a0,a1
[ 	]+[0-9a-f]+:[ 	]+63f5d513[ 	]+rori[ 	]+a0,a1,0x3f
[ 	]+[0-9a-f]+:[ 	]+63f5d513[ 	]+rori[ 	]+a0,a1,0x3f
[ 	]+[0-9a-f]+:[ 	]+6005d51b[ 	]+roriw[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+61f5d51b[ 	]+roriw[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+60c5d53b[ 	]+rorw[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+6005d51b[ 	]+roriw[ 	]+a0,a1,0x0
[ 	]+[0-9a-f]+:[ 	]+61f5d51b[ 	]+roriw[ 	]+a0,a1,0x1f
[ 	]+[0-9a-f]+:[ 	]+60c5953b[ 	]+rolw[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ac59533[ 	]+clmul[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ac5b533[ 	]+clmulh[ 	]+a0,a1,a2
[ 	]+[0-9a-f]+:[ 	]+0ac5a533[ 	]+clmulr[ 	]+a0,a1,a2
