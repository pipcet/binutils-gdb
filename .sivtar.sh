autoreconf2.64 -vif && CC="gcc" CFLAGS="-rdynamic -g3 -O0" ./configure && make -k &&
    (cd gdb; autoreconf2.64 -vif && CC="gcc" CFLAGS="-rdynamic -g3 -O0" ./configure --enable-target=x86_64-pc-linux-gnu --host=x86_64-pc-linux-gnu --target=x86_64-pc-linux-gnu --with-perl=`which perl` &&  make -k && sudo make -k install) &&
    ./x86_64-pc-linux-gnu-gdb --ex 'perl warn "this is from GDB"' --batch
