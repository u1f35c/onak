#!/usr/bin/perl

# sig2dot v0.8 (c) Darxus@ChaosReigns.com, released under the GPL
# Download from: http://www.chaosreigns.com/debian-keyring
#
# Parses the (gpg) debian-keyring 
# (http://www.debian.org/Packages/unstable/misc/debian-keyring.html) to a format
# suitable for use by dot or neato (package name graphviz,
# http://www.research.att.com/sw/tools/graphviz/) like so:
#
# gpg --list-sigs --keyring /usr/share/keyrings/debian-keyring.gpg | ./sig2dot.pl > debian-keyring.dot
# neato -Tps debian-keyring.dot > debian-keyring.neato.dot.ps
# dot -Tps debian-keyring.dot > debian-keyring.dot.dot.ps

while ($line = <STDIN>)
{
  chomp $line;
  if ($line =~ m#([^ ]+) +[^ ]+ +[^ ]+ +([^<]+)#)
  {
    $type = $1;
    $name = $2;
    chop $name;
    #print "type:$type:name:$name:\n";

    if ($type eq "pub")
    {
      $owner = $name; 
    }

    if ($type eq "sig" and $name ne $owner and $name ne '[User id not found')
    {
      push (@{$sigs{$owner}},$name);
      push (@names,$name,$owner);
    }
  } else {
    print STDERR "Couldn't parse: $line\n";
  }
}

print "digraph \"debian-keyring\" {\n";

undef %saw;
@saw{@names} = ();
@names = keys %saw;
undef %saw;

for $owner (sort {$sigs{$a} <=> $sigs{$b}} keys %sigs)
{
  undef %saw;
  @saw{@{$sigs{$owner}}} = ();
  @{$sigs{$owner}} = keys %saw;
  undef %saw;

  #print STDERR scalar(@{$sigs{$owner}})," $owner\n";
  $count{$owner} = scalar(@{$sigs{$owner}});
}

open (STATS,">stats.html");
print STATS "<html><body><table border=1>\n";

for $owner (sort {$count{$b} <=> $count{$a}} keys %sigs)
{
  print STATS "<tr><td>$owner<td>$count{$owner}<td><img src=\"/images/pipe0.jpg\" height=15 width=",$count{$owner} * 20,">\n";
}

print STATS "</table></body></html>\n";
close STATS;

print "node [style=filled]\n";
for $name (@names)
{
  if ($count{$name} > 20)
  {
    print "\"$name\" [color=red]\n";
  } elsif ($count{$name} > 8)
  {
    print "\"$name\" [color=blue]\n";
  }
}
print "node [style=solid]\n";

for $owner (sort keys %sigs)
{
  for $name (@{$sigs{$owner}})
  {
    print "\"$name\" -> \"$owner\" [len=5]\n";
  }
}

print "}\n";


