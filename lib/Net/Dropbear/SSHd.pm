package Net::Dropbear::SSHd;

use strict;
use v5.12;
our $VERSION = '0.1';

use Child;

use autodie;
use Carp;
use Moo;
use Types::Standard qw/ArrayRef HashRef GlobRef Str Int Bool InstanceOf/;

has addrs => (
  is => 'rw',
  isa => ArrayRef[Str],
  coerce => sub { ref $_[0] ? $_[0] : [ $_[0] ] },
);

has keys => (
  is => 'rw',
  isa => ArrayRef[Str],
  coerce => sub {
    my $value = shift;
    $value = ref $value ? $value : [ $value ];
    foreach my $key ( @$value )
    {
      carp "Key file does not exist: $key"
        if !-e $key;
    }
    return $value;
  },
);

has debug          => ( is => "rw", isa => Bool, default => 0, );
has forkbg         => ( is => "rw", isa => Bool, default => 0, );
has usingsyslog    => ( is => "rw", isa => Bool, default => 0, );
has inetdmode      => ( is => "rw", isa => Bool, default => 0, );
has norootlogin    => ( is => "rw", isa => Bool, default => 1, );
has noauthpass     => ( is => "rw", isa => Bool, default => 1, );
has norootpass     => ( is => "rw", isa => Bool, default => 1, );
has allowblankpass => ( is => "rw", isa => Bool, default => 0, );
has delay_hostkey  => ( is => "rw", isa => Bool, default => 0, );
has domotd         => ( is => "rw", isa => Bool, default => 0, );
has noremotetcp    => ( is => "rw", isa => Bool, default => 1, );
has nolocaltcp     => ( is => "rw", isa => Bool, default => 1, );

has hooks => (
  is => 'ro',
  isa => HashRef,
  default => sub { {} },
);

has child => (
  is => 'rw',
  isa => InstanceOf['Child::Link::Proc'],
);

has comm => (
  is => 'rwp',
  isa => GlobRef,
);

sub is_running
{
  my $self = shift;
  return defined $self->child;
}

sub run
{
  my $self = shift;
  my $child_hook = shift;

  if (defined $child_hook && ref $child_hook ne 'CODE')
  {
    croak '$child_hook was not a code ref when calling run';
  }

  use Socket;
  use IO::Handle;
  socketpair(my $child_comm, my $parent_comm, AF_UNIX, SOCK_STREAM, PF_UNSPEC);

  my $child = Child->new(sub {
    my $parent = shift;
    $0 .= " [Net::Dropbear Child]";

    $parent_comm->close;
    $self->_set_comm($child_comm);

    require Net::Dropbear::XS;

    Net::Dropbear::XS->setup_svr_opts($self);

    $child_hook->($parent)
      if defined $child_hook;

    Net::Dropbear::XS->svr_main();

    # Should never return
    croak 'Unexpected return from dropbear';
  });

  $self->child($child->start);
  $child_comm->close;
  $self->_set_comm($parent_comm);

  return;
}

sub kill
{
  my $self = shift;
  if ($self->is_running)
  {
    $self->child->kill(15);
  }
}

sub wait
{
  my $self = shift;
  if ($self->is_running)
  {
    $self->child->wait;
  }
}

sub auto_hook
{
  my $self = shift;
  my $hook = shift;

  if (exists $self->hooks->{$hook})
  {
    return $self->hooks->{$hook}->(@_);
  }

  return Net::Dropbear::XS::HOOK_CONTINUE();
}


1;
__END__

=encoding utf-8

=head1 NAME

Net::Dropbear::SSHd - Embed and control a Dropbear SSH server inside of perl

=head1 SYNOPSIS

  use Net::Dropbear::SSHd;
  
  Net::Dropbear::XS::gen_key($key_filename);
  
  my $sshd = Net::Dropbear::SSHd->new(
    addrs      => '2222',
    keys       => $key_filename,
    hooks      => {
      on_log => sub
      {
        my $priority = shift;
        my $msg      = shift;
        warn( "$msg\n" );
        return HOOK_CONTINUE;
      },
    }
  );
  
  $sshd->run;
  $sshd->wait;

=head1 DESCRIPTION

Net::Dropbear::SSHd allows you to embed and control an SSH server (using Dropbear) from perl.

=head2 Motivation

Maybe you're asking yourself why you'd want to do that? Imagine that you want
to run a service where you let users run remote commands over SSH, say SFTP
or git. Also imagine that you'd like maintain the users or public keys in a
database instead of in a file.  A good example of this behavior would be
Github and other cloud-based git-over-ssh solutions.

I'm pretty confident that one could get OpenSSH to do this, but I saw a couple
problems:

=over

=item The user must be a real user

Any user that wants to connect must be a real user at the OS level. Managing
multiple users, let alone millions, is a nightmare.

=item OpenSSH really likes running as root

Until recently, running as non-root was even possible. It's now possible,
but a lot of interesting features are restricted.

=item Authorized keys can be provided through a script owned by root

A continuation of the point above, but in order to enable OpenSSH to verify
a key, a script can be provided. This script (and all directories leading
to the script) must be owned by root.

=item OpenSSH (and SSH) have a lot of options

And while that is a good thing in general, in this particular case I was not
confident that I could tune all the options correctly to make sure I wasn't
completely securing the system.

=back

I really didn't want to provide outside users with a clever way to
gain access to my machine. That's where this module comes into play. With
C<Net::Dropbear::SSHd> you can control the entire lifecycle of SSHd, including
which usernames are accpeted, which public keys are authorized and what
commands are ran.

=head1 CONSTRUCTOR

=head2 new

  my $sshd = Net::Dropbear::SSHd({ %params });

Returns a new C<Net::Dropbear::SSHd> object.

=head3 Attributes

=over

=item addrs

A string or an array of addresses to bind to. B<Default>: Nothing

=item keys

An array of server keys for Dropbear. B<Default>: Generate keys automatically

=item hooks

A hashref of coderef's that get called during key points of the SSH server
session.

=back

=head3 Dropbear options

=over

=item debug

=item forkbg

=item usingsyslog

=item inetdmode

=item norootlogin

=item noauthpass

=item norootpass

=item allowblankpass

=item delay_hostkey

=item domotd

=item noremotetcp

=item nolocaltcp

=back

=head2 Hooks

=head1 METHODS

=head1 CHILD PROCESSES

=head1 AUTHOR

Jon Gentle E<lt>atrodo@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2015- Jon Gentle

=head1 LICENSE

This is free software. You may redistribute copies of it under the terms of the Artistic License 2 as published by The Perl Foundation.

=head1 SEE ALSO

=cut
