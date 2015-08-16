use strict;
use Test::More;
use File::Temp ();

use Net::Dropbear::SSHd;
use Net::Dropbear::XS;
use Net::OpenSSH;

my $port = int(rand(10000) + 1024);
my $key_fh = File::Temp->new( template => "net_dropbear_sshd_XXXXXXXX" );
my $key_filename = $key_fh->filename;
undef $key_fh;

Net::Dropbear::XS::gen_key($key_filename);

END { unlink $key_filename };

my $sshd = Net::Dropbear::SSHd->new(
  addrs => $port,
  allowblankpass => 1,
  noauthpass => 0,
  keys => $key_filename,
  hooks => {
    on_username => sub { return 0; },
    on_shadow_fill => sub { $_[0] = crypt('', 'aa'); return 0; },
  },
);

$sshd->run;

diag("OpenSSH");
my $ssh = Net::OpenSSH->new("localhost:$port", password => '', user  => $port, master_opts => [ -o => "UserKnownHostsFile /dev/null", -o => "StrictHostKeyChecking no", '-v' ]);

diag("OpenSSH Back");
#diag(Data::Dumper::Dumper($ssh));

is($ssh->check_master, 1, 'Able to connect to Dropbear');
isnt($ssh->error, undef, 'Connected to Dropbear without error');

diag("Cleanup: kill");
$sshd->kill;

diag("Cleanup: wait");
$sshd->wait;

ok 1;

done_testing;
