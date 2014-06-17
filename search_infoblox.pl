#!/usr/bin/perl
# A program that retrieves Firewall NAT Entries and F5 Server Pool entries from Infoblox
# Author: Mark Jayson R. Alvarez

use 5.010;
use strict;
use warnings;
use File::Slurp;
use Data::Dumper;
use JSON;	
use LWP::UserAgent;


my $ua = new LWP::UserAgent(keep_alive => 1);
$ua->credentials('infoblox_hostname_changethis:80', '', 'username_changethis', 'password_changethis');
$ua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');
$ua->proxy('http', 'http://127.0.0.1:8080/');
$ua->default_header('Referer' => "http://infoblox_url_changethis/Network");  
  
my $totalitemcount = 0;
my $maxitem = 58;
my $pageno = 1;
my $currentitemcount = 1;
my $idcounter = 0;
my $natcounter = 0;

my %ipmappings;
my @ipmappings;
my %serverpool;


open IPMAPPINGS, ">", "ip_mappings_all.csv" or die $!;
my $hostcounter = 0;


my $json_count = get_json(\$ua, 1, 58, 'FIREWALL', '*');
for (@$json_count){
    next if $$_{ResultType} ne 'FIREWALL';
    $totalitemcount = $$_{TotalItemCount};
}
 
 
print IPMAPPINGS "External IP,Internal VIP,Server IPs\n";
while ($currentitemcount < $totalitemcount){
   my $json = get_json(\$ua, $pageno, $maxitem, 'FIREWALL', '*');
   $currentitemcount = $currentitemcount + $maxitem;

   for (@$json){
       next if $$_{ResultType} ne 'FIREWALL';
       for(@{$$_{Items}}){
                 
          ++$idcounter;
          say "$idcounter.) $$_{Id}";
          $ua->default_header('Referer' => "http://infoblox_url_changethis/Network/Netmri/FirewallInfo?deviceId=" . $$_{Id} . "&searchInput=*");   
          my $natreq = HTTP::Request->new(POST => 'http://infoblox_url_changethis/Network/NETMRI/FirewallIPTrace');
          $natreq->content_type('application/x-www-form-urlencoded; charset=UTF-8');
          $natreq->content('ipAddress=*&deviceId=' . $$_{Id});
          my $natres = $ua->request($natreq);
          my @list = $natres->content() =~ /externalIP\'\:\s+\'(\d+\.\d+\.\d+\.\d+)\'\,\s+\'internalIP\'\:\'(\d+\.\d+\.\d+\.\d+)\'\}/g;
         for (@list){
            push @ipmappings, $_;
         }
         %ipmappings = @ipmappings;
         foreach my $external (keys %ipmappings){
             ++$natcounter;
              say "$natcounter.)" . $external . " :: " . $ipmappings{$external};
              ++$hostcounter;
              $serverpool{$ipmappings{$external}} = get_vipservers($ipmappings{$external}); 
              my $servers = join(" ", @{$serverpool{$ipmappings{$external}}});
              $| = 1;
              IPMAPPINGS->autoflush(1);
              print IPMAPPINGS "$external,$ipmappings{$external},$servers\n"; 
              for (@{$serverpool{$ipmappings{$external}}}){
                 print " - $_\n";
              }
       
         }
       } 

   }

    ++$pageno;
} 



######################################



sub get_vipservers{
   
   my %servers;
   my $vip = shift;
   my $json = get_json(\$ua, $pageno, $maxitem, '*', $vip);

   for (@$json){
       next if $$_{ResultType} ne 'VIP';
       for(@{$$_{Items}}){ 
           
          $ua->default_header('Referer' => "http://infoblox_url_changethis/Network/Device/VirtualServerInfo?name=" . $$_{Name}. "&deviceIP=" . $$_{SourceId});   
           my $serverreq = HTTP::Request->new(POST => 'http://infoblox_url_changethis/Network/Device/VirtualServerInfoResources');
           $serverreq->content_type('application/x-www-form-urlencoded; charset=UTF-8');
           my $content = 'name=' . $$_{Name} . '&deviceIP=' . $$_{SourceId};
           $serverreq->content($content);
           my $serverres = $ua->request($serverreq);   
           (my @ip) = $serverres->content() =~ /(\d+\.\d+\.\d+\.\d+\:\d+)/g;          
           for (@ip){
               $servers{$_} = undef;
           }
           
 
       }  	
   }
   


my @servers = keys %servers;   
return (\@servers);

}




sub get_json{
    
  my $ua = shift;
  my $pagenum = shift;
  my $pagesize = shift;
  my $devicetype = shift;
  my $qip = shift;
  my $submitreq = HTTP::Request->new(POST => 'http://infoblox_url_changethis/Network/Search/GetResult');
  $submitreq->content_type('application/json');
  $submitreq->content('{"q":"' . $qip . '","types":["*"],"devices":["' . $devicetype . '"],"ResultOptions":{"PageNum":' . $pagenum . ',"PageSize":' . $pagesize . ',"SortParam":"","SortOrder":"ASC"},"hint":"searchall"}');  
  my $submitres = $$ua->request($submitreq);   
  my $json_string;
  my $json_ref;
  $json_string = $submitres->content();
  my $temp_json;
  
my $test_json = eval {
                          $temp_json = from_json ($json_string); 
                };   

while (!$test_json){
    say "SERVER CLOSED CONNECTION. RETRYING...";
    sleep 1;
    $submitres = $$ua->request($submitreq);  
    $json_string = $submitres->content();
    $test_json = eval {
          $temp_json = from_json ($json_string); 
    };     
}


$json_ref = from_json ($json_string); 
  return $json_ref;
}

