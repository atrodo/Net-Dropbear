use strict;
use Test::More;
use Net::Dropbear::SSHd;
use Net::OpenSSH;

# replace with the actual test

my $sshd = Net::Dropbear::SSHd->new;

$sshd->run;

my $ssh = Net::OpenSSH->new($host);
my $sftp = $ssh->sftp();
$sftp->error and die "SFTP failed: " . $sftp->error;

$sshd->kill;
$sshd->wait;

ok 1;

done_testing;
