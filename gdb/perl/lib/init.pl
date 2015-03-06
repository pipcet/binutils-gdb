use FFI::Platypus::Declare;

lib undef;

eval {
  attach 'perl_linespec' => [] => 'string';
};

if($@) {
  warn $@;
  warn "Have you compiled gdb with the -rdynamic option?";
}

my $PERL_LINESPEC = perl_linespec;
