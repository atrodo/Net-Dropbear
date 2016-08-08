use strict;
use Test::More;
use File::Temp ();

use Net::Dropbear::SSHd;
use Net::Dropbear::XS;
use IPC::Open3;
use Try::Tiny;
use IO::Pty;
use IO::Select;

our $planned = 0;
our $port    = int( rand(10000) + 1024 );
our $key_fh  = File::Temp->new( template => "net_dropbear_sshd_XXXXXXXX" );
our $key_filename = $key_fh->filename;
undef $key_fh;

Net::Dropbear::XS::gen_key($key_filename);

END { unlink $key_filename }

our $sshd;

chmod 0500, glob("$FindBin::Bin/test*");

my $last_pty;
$SIG{'CHLD'} = 'IGNORE';

sub needed_output
{
  my %test_map;

  my $s = IO::Select->new();

  while (@_)
  {
    my $io     = shift // $sshd->comm;
    my $needed = shift;

    my %needed = %$needed;

    $planned += keys %needed;

    my %match   = map { $_ => $needed{$_} } grep { $_ !~ m/^!/ } keys %needed;
    my %unmatch = map { $_ => $needed{$_} } grep { $_ =~ m/^!/ } keys %needed;

    $s->add($io);
    $io->blocking(0);

    $test_map{$io} = {
      match => \%match,
      unmatch => \%unmatch,
    };
  }

  my $result = "";
  my $had_error;

  try
  {
    local $SIG{ALRM} = sub { die; };

    if ( defined $last_pty && $last_pty->opened && !exists $test_map{$last_pty})
    {
      $s->add($last_pty);
      $last_pty->blocking(0);
    }

    alarm 4;

SELECT:
    while ( my @fds = $s->can_read(4) )
    {
      foreach my $fd (@fds)
      {
        my $fileno = $fd->fileno;

        if (!defined $test_map{$fd})
        {
          while ( my $line = $fd->getline )
          {
            note(" #$fd#$fileno# $line");
          }
          if ($fd->eof)
          {
            note(" $fd removed");
            $s->remove($fd);
          }
          next;
        }

        my $io = $test_map{$fd};
        my $match = $io->{match};
        my $unmatch = $io->{unmatch};

        while ( my $line = $fd->getline )
        {
          note(" #$fd#$fileno# $line");

          $result .= $line;
          chomp $line;
          foreach my $key ( keys %$unmatch )
          {
            my $re = $key;
            $re =~ s/^!//;
            if ( $line =~ m/^ \Q$re\E/xms )
            {
              ok( 0, delete $unmatch->{$key} );
              $had_error = 1;
            }
          }
          foreach my $key ( keys %$match )
          {
            if ( $line =~ m/^ \Q$key\E/xms )
            {
              ok( 1, delete $match->{$key} );
            }
          }
        }

        if (keys(%$match) == 0)
        {
          note(" $fd removed matched");
          $s->remove($fd);
        }

        if (!$fd->opened)
        {
          note(" $fd removed eof");
          $s->remove($fd);
        }
      }

      alarm 4;
    }
    alarm 0;
  }
  catch
  {
    note($_);
  }
  finally
  {
    foreach my $io ( values %test_map )
    {
      my $match = $io->{match};
      my $unmatch = $io->{unmatch};
      foreach my $key ( keys %$match )
      {
        ok( 0, $match->{$key} );
        $had_error = 1;
      }
      foreach my $key ( keys %$unmatch )
      {
        ok( 1, $unmatch->{$key} );
      }
    }
  };

  if ($had_error)
  {
    diag( "Output Seen: " . join( "\n #\t", split( /\n/, $result ) ) );
  }

  return $result;
}

sub ssh
{
  my %params = @_;

  my $username = $params{username} || $port;
  my $password = $params{password};
  my $key      = $params{key};
  my $cmd      = $params{cmd};

  my @ssh_cmd = (
    'ssh',
    '-oUserKnownHostsFile=/dev/null',
    '-oStrictHostKeyChecking=no',
    $password ? () : ('-oPasswordAuthentication=no'),
    '-oNumberOfPasswordPrompts=1',
    $key ? ( "-i", $key ) : (),
    "-p$port",
    '-T',

    #'-v',
  );

  my $pty     = IO::Pty->new;
  my $ssh_pid = fork;

  if ( !$ssh_pid )
  {
    $pty->make_slave_controlling_terminal();
    my $slave = $pty->slave();
    close $pty;
    open( STDIN,  "<&" . $slave->fileno() );
    open( STDOUT, ">&" . $slave->fileno() );
    open( STDERR, ">&" . $slave->fileno() );

    exec( @ssh_cmd, "$username\@localhost", $cmd ? $cmd : 'false' );
  }

  $pty->close_slave();
  $pty->set_raw();

  if ( defined $password )
  {
    my $buff;
    note("Sending password");
    while ( $pty->sysread( $buff, 1024 ) )
    {
      note("SSH output: $buff");
      if ( $buff =~ m/password:/ )
      {
        $pty->say($password);
        last;
      }
    }
  }

  $last_pty = $pty;
  return (
    pty => $pty,
    pid => $ssh_pid,
  );
}

1;
