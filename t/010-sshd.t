use strict;
use Test::More;
use File::Temp ();

use Net::Dropbear::SSHd;
use Net::Dropbear::XS;
use IPC::Open3;
use IO::Pty;
use Try::Tiny;

use FindBin;
require "$FindBin::Bin/Helper.pm";

our $port;
our $key_fh;
our $key_filename;
our $sshd;
our $planned;

use POSIX qw/WNOHANG/;

my $sshd = Net::Dropbear::SSHd->new(
  addrs          => $port,
  noauthpass     => 0,
  keys           => $key_filename,
);

$sshd->run;

cmp_ok( waitpid( $sshd->child->pid, WNOHANG ), '>=', 0, 'SSHd started' );

$sshd->kill;
$sshd->wait;

cmp_ok( waitpid( $sshd->child->pid, WNOHANG ), '<', 0, 'SSHd stopped' );

done_testing($planned);
