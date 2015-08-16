package Net::Dropbear::SSHd;

use strict;
use v5.12;
our $VERSION = '0.1';

use Child;

use Carp;
use Moo;
use Types::Standard qw/ArrayRef HashRef Str Int Bool InstanceOf/;

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

sub is_running
{
  my $self = shift;
  return defined $self->child;
}

sub run
{
  my $self = shift;

  my $child = Child->new(sub {
    my $parent = shift;
    $0 .= " [Net::Dropbear Child]";
    use Data::Dumper;
    require Net::Dropbear::XS;
    warn Data::Dumper::Dumper($self);
    my $a = Net::Dropbear::XS->setup_svr_opts($self);
    warn Data::Dumper::Dumper($a);
    #Net::Dropbear::XS::addportandaddress($self->port);
    Net::Dropbear::XS->svr_main();
  });
  $self->child($child->start);
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

    warn "Calling hook $self, $hook\n";
  if (exists $self->hooks->{$hook})
  {
    warn "Calling hook $hook\n";
    return $self->hooks->{$hook}->(@_);
  }

  return Net::Dropbear::XS::DROPBEAR_FAILURE();
}

1;
__END__

=encoding utf-8

=head1 NAME

Net::Dropbear - Blah blah blah

=head1 SYNOPSIS

  use Net::Dropbear;

=head1 DESCRIPTION

Net::Dropbear is

=head1 AUTHOR

Jon Gentle E<lt>cpan@atrodo.orgE<gt>

=head1 COPYRIGHT

Copyright 2015- Jon Gentle

=head1 LICENSE

This is free software. You may redistribute copies of it under the terms of the Artistic License 2 as published by The Perl Foundation.

=head1 SEE ALSO

=cut
