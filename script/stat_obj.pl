#!/usr/bin/perl
use strict;
use warnings;
use constant delta => 5;

my $pre = 0;
my $cur = 0;
my %dict = ();

while(<>){

    if (/(\d{10})\.\d{6}\sccnd\[\d+\]:\sreceived\snew\sContentObject/) {
	#print $1,"\n";
	#print $pre, "\n";
	$cur = $pre = $1 if (0 == $pre);

	if (int $1 < int $pre + delta) {
	    $dict{$cur}++;
	} else {
	    $cur = $1;
	    $dict{$cur} = 1;
	}
	$pre = $1;
    }

}

print "$_\t$dict{$_}\n" foreach (sort {$a <=> $b} keys %dict);
#print "$_\n" foreach (sort {$a <=> $b} values %dict);
