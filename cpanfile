requires 'perl', '5.008008';

requires 'Moo', '2.000';
requires 'Try::Tiny';
requires 'Types::Standard';
requires 'Child';

on test => sub {
  requires 'Test::More', '0.96';
  requires 'IO::Pty';
};
