#ld: -T pr22267.t
#nm: -n
#xfail: bfin-*-linux* frv-*-linux*

# Some targets may zero-extend 32-bit address to 64 bits.
#...
0*f+00 A foo
#pass
