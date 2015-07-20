requires 'perl', '5.012000';

requires 'Moo', '2.000';
requires 'Types::Standard';
requires 'Child';

on test => sub {
  requires 'Test::More', '0.96';
  requires 'Net::OpenSSH';
  requires 'Net::SFTP::Foreign';
};
