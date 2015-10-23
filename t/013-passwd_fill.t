use strict;
use Test::More;
use File::Temp ();

use Net::Dropbear::SSHd;
use Net::Dropbear::XS;
use IPC::Open3;
use Try::Tiny;

use FindBin;
require "$FindBin::Bin/Helper.pm";

our $port;
our $key_fh;
our $key_filename;
our $sshd;
our $planned;

my $start_str      = "ON_START";
my $ok_str         = "IN on_passwd_fill";
my $not_forced_str = "Not forcing username";
my $forced_str     = "Forcing username";

$sshd = Net::Dropbear::SSHd->new(
  addrs      => $port,
  noauthpass => 0,
  keys       => $key_filename,
  hooks      => {
    on_log => sub
    {
      shift;
      $sshd->comm->printflush( shift . "\n" );
      return 1;
    },
    on_start => sub
    {
      $sshd->comm->printflush("$start_str\n");
      return 1;
    },
    on_passwd_fill => sub
    {
      my $auth_state = shift;
      my $username   = shift;
      $sshd->comm->printflush("$ok_str\n");
      if ( $username ne $port )
      {
        $sshd->comm->printflush("$forced_str\n");
        $auth_state->pw_name($port);
      }
      else
      {
        $sshd->comm->printflush("$not_forced_str\n");
      }

      if ( $username eq 'shell' )
      {
        note('Setting the shell to something invalid');
        $auth_state->pw_shell('/');
      }

      return 1;
    },
  },
);

$sshd->run;

needed_output(
  {
    $start_str => 'Dropbear started',
  }
);

my @ssh_cmd = (
  'ssh',
  '-oUserKnownHostsFile=/dev/null',
  '-oStrictHostKeyChecking=no',
  '-oPasswordAuthentication=no',
  "-p$port",
);

{
  my $ssh_pid = open3(
    '/dev/null', my $ssh_out, undef,
    @ssh_cmd,    "$port\@localhost",
  );

  needed_output(
    {
      $ok_str         => 'Got into the passwd hook',
      $not_forced_str => 'Did not force username',
      "Exit before auth (user '$port', 0 fails)" =>
          'SSH quit with a good username',
    }
  );

  note("SSH output");
  note($_) while <$ssh_out>;

  kill($ssh_pid);
}

{
  my $ssh_pid = open3(
    '/dev/null', my $ssh_out, undef,
    @ssh_cmd,    "a$port\@localhost",
  );

  needed_output(
    {
      $ok_str     => 'Got into the passwd hook',
      $forced_str => 'Did force username',
      "Exit before auth (user '$port', 0 fails)" =>
          'SSH quit with an overridden bad username',
    }
  );

  note("SSH output");
  note($_) while <$ssh_out>;

  kill($ssh_pid);
}

{
  my $ssh_pid = open3(
    '/dev/null', my $ssh_out, undef,
    @ssh_cmd,    "shell\@localhost",
  );

  needed_output(
    {
      $ok_str     => 'Got into the passwd hook',
      $forced_str => 'Did force username',
      "User '$port' has invalid shell, rejected" =>
          'SSH errored on a bad shell',
    }
  );

  note("SSH output");
  note($_) while <$ssh_out>;

  kill($ssh_pid);
}

$sshd->kill;
$sshd->wait;

done_testing($planned);
