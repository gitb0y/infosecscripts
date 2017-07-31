#!/usr/bin/perl
#
#################################################################################
#                                                                               #
# Description: A program that automates submission of CA Service Desk tickets   #
# for PCI vulnerability remediation with Qualys.                                #
# Author: Mark Jayson R. Alvarez (mark.alvarez123@gmail.com)                    #
# Creation date: Aug. 2 2013                                                    #
# Usage: #perl qualysparser.pl                                                  #
#                                                                               #
#    Copyright (C) <2014>  <Mark Jayson R. Alvarez>                             #
#                                                                               #
#    This program is free software: you can redistribute it and/or modify       #
#    it under the terms of the GNU General Public License as published by       #
#    the Free Software Foundation, either version 3 of the License, or          #
#    (at your option) any later version.                                        #
#                                                                               #
#    This program is distributed in the hope that it will be useful,            #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of             #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
#    GNU General Public License for more details.                               #
#                                                                               #
#    You should have received a copy of the GNU General Public License          #
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.      #
#                                                                               #
#################################################################################

use 5.014;
use strict;
use warnings;
use threads;
use threads::shared; 
#use diagnostics; 
use LWP::UserAgent;
use Cwd;
use HTTP::Cookies;
use Spreadsheet::XLSX;
use POSIX qw(strftime);
use HTML::Entities;
use Text::Tabs;
use URI::Escape;
use Excel::Writer::XLSX; 
use File::Copy;
use Net::IP;   
use Term::ReadKey;
use Data::Dumper;
use XML::Simple;
use XML::LibXML;
use Time::HiRes qw/time/;
use Date::Parse;
use Time::Piece;
use DateTime::Format::ISO8601;
use File::Find;
use File::Slurp;
use HTTP::Async;
use Date::Calc qw(Delta_Days);
use Term::ProgressBar 2.00;
use Getopt::Long;
use Config::Simple;
use Socket;








#######################   DEFAULT CONFIG FILE   ############################################

my %Config;
my $cfg;
my $readconfig = eval {
                        $cfg = new Config::Simple('qualys.conf');
                };   

if (!$readconfig){
    say "\n***   CONFIG FILE NOT FOUND. CREATING ONE WITH THE DEFAULT VALUES ***\n\n";
    $cfg = new Config::Simple(syntax=>'http'); 
    $cfg->param("email_domain", 'My.Co.com');
    $cfg->param("domain_username", 'mydomain\username');
    $cfg->param("domain_password", 'mypassword');
    $cfg->param("qualys_username", 'qualysusername');
    $cfg->param("qualys_password", 'qualyspassword' );
    $cfg->param("tickets_path", '//absolute\path\to\01 Vulnerability Assessment Reports\submitted tickets');
    $cfg->param("region_ip_blocks", '//absolute\path\to\Tools\Qualys CA Service Desk Integration\asset group IPs');
    $cfg->param("ip_mappings", '//absolute\path\to\Tools\Qualys CA Service Desk Integration\ip_mappings.xlsx');
    $cfg->param("cve_data", '//absolute\path\to\Tools\Qualys CA Service Desk Integration\cve_data.xlsx');
    $cfg->param("xml_folder", ' //absolute\path\to\04 V&EM\01 Vulnerability Assessment Reports\xml scan results');
    $cfg->param("assignee_group", 'IT Security Monitoring Global');
    $cfg->param("affected_customer", 'IT Security Monitoring Global');
    $cfg->param("request_area", 'IT.Security.General');
    $cfg->param("process_mode", []);
    $cfg->param("process_nonpci", []);
    $cfg->param("selected_vulns", []);
    $cfg->param("selected_regions", []);   
    $cfg->param("latest_result_date", []); ### IN YYYY-MM-DD FORMAT
    $cfg->param("month_filter", []);  ### IN MM FORMAT
    $cfg->param("notify_emails", []);    
    $cfg->param("max_scan_results", []);
    $cfg->param("log_file", '//absolute\path\to\04 V&EM\Tools\Qualys CA Service Desk Integration\vulns_report.log');
    $cfg->param("write_log", 'no');
    $cfg->write("qualys.conf");     
    $cfg->autosave(1);
    
    say "New configuration file was written to 'qualys.conf'.\nEdit this file according to your preference before running the script.\nExiting...\n";
    exit;

}





############################  OPTIONS AVAILABLE VIA COMMAND-LINE ARGUMENTS  ########################################
 

my $debug = 'no';
my $process_anontargets = '';
my $scanner_account = '';
my $assignee_group;
my $write_log;
my $log_file;
my $notify_emails;
my $selectedregions;
my $username;
my $process_nonpci;
my $origselectedvulns;
my $process_mode;
my $target_date;
my $update_status = 'yes';
my $copyright = '';

GetOptions ('copyright' => \$copyright, 'update-status:s' => \$update_status, 'debug:s' => \$debug, 'target-date:s' => \$target_date, 'process-mode:i' => \$process_mode, 'selected-vuln:s@' => \$origselectedvulns, 'notify-email:s@' => \$notify_emails, 'selected-region:s@' => \$selectedregions, 'process-nonpci:s' => \$process_nonpci, 'assignee-group:s' => \$assignee_group, 'write-log:s' => \$write_log, 'log-file:s' => \$log_file);


my $copyright_shortwarning = <<"WARNING";


<submit_ticket.pl>  Copyright (C) <2014>  <Mark Jayson R. Alvarez>

    This program comes with ABSOLUTELY NO WARRANTY;
    This is free software, and you are welcome to redistribute it
    under certain conditions; type 'perl submit_ticket.pl --copyright' for details.

WARNING

my $copyright_notice = <<COPYRIGHT;

#################################################################################
#                                                                               #
#    Copyright (C) <2014>  <Mark Jayson R. Alvarez>                             #
#                                                                               #
#    This program is free software: you can redistribute it and/or modify       #
#    it under the terms of the GNU General Public License as published by       #
#    the Free Software Foundation, either version 3 of the License, or          #
#    (at your option) any later version.                                        #
#                                                                               #
#    This program is distributed in the hope that it will be useful,            #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of             #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
#    GNU General Public License for more details.                               #
#                                                                               #
#    You should have received a copy of the GNU General Public License          #
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.      #
#                                                                               #
#################################################################################

COPYRIGHT

if ($copyright){
   say $copyright_notice;
   exit;
}else{
   say $copyright_shortwarning;
   sleep 3;
}



$selectedregions = join (' ', @{$selectedregions}) if ref($selectedregions);
if (!defined $process_mode or $process_mode eq ''){
     $process_mode = $cfg->param("process_mode");
}

if (!defined $target_date or $target_date eq ''){
     $target_date = $cfg->param("latest_result_date");
}


if (!defined $assignee_group or $assignee_group eq ''){
     $assignee_group = $cfg->param("assignee_group");
}

if (!defined $write_log or $write_log eq ''){
     $write_log = $cfg->param("write_log");
}

if (!defined $log_file or $log_file eq ''){
     $log_file = $cfg->param("log_file");
}


############################# DOMAIN LOGIN AND QUALYS LOGIN PROMPT ####################################

my $password = $cfg->param("domain_password");
 if (!ref($cfg->param("domain_username"))){
    $username = $cfg->param("domain_username");
    
 }else{
    $username = `whoami`;
 }
my $qualysusername = $cfg->param("qualys_username");
my $qualyspassword = $cfg->param("qualys_password");


chomp $username if $username ne ''; 

print "\nLogin to Service Desk to submit tickets:\n\n" unless !ref($username) && !ref($password); 
(ref ($username)) && print "Username: ";
(!ref($username)  && ref($password)) && print "Username: $username\n";

ReadMode('normal');
$username = ReadLine(0) unless !ref($username);
chomp $username if defined $username;
print (!ref($password)?"":"Password: ");
ReadMode('noecho');
$password = ReadLine(0) unless (!ref($password));
chomp $password if defined $password;

 
print "\n\n\n\nEnter your Qualys login below:\n\n" unless !ref($qualysusername) && !ref($qualyspassword);
(ref($qualysusername)) && print "Username: ";
(!ref($qualysusername) && ref($qualyspassword)) && print "Username: $qualysusername\n";
ReadMode('normal');
$qualysusername = ReadLine(0) unless !ref($qualysusername);
chomp $qualysusername if defined $qualysusername;
print (!ref($qualyspassword)?"":"Password: ");
ReadMode('noecho');
$qualyspassword = ReadLine(0) unless (!ref($qualyspassword));
chomp $qualyspassword if defined $qualyspassword;
print "\n\n\n" unless !ref($password);


my @login_status = qualys_session('login');
if (${$login_status[0]} =~ /Logged in/){
   my $res = qualys_session('logout', $login_status[1]);
}else{
   say "\n\nINVALID QUALYS USERNAME AND/OR PASSWORD. EXITING...";
   exit;
}
###########################################################################################################


##########################  NOTIFICATION EMAIL SENDER AND RECEIVER  ###################################

my $email_domain = $cfg->param("email_domain");

$notify_emails = join (',', @{$notify_emails}) if ref($notify_emails);


if (!defined $notify_emails or $notify_emails eq ''){
   my @notify_emails = $cfg->param("notify_emails");
    if (scalar @notify_emails == 0){
        my $login_name = `whoami`;
        chomp $login_name;
        $login_name =~ s/.*\\//;
        $notify_emails = $login_name . '@' . $email_domain;
   }else{
      $notify_emails = join (',', @notify_emails);
   }
}


(my $mailfrom) = $username =~ /.*\\(.*?)$/;
$mailfrom = $mailfrom . '@' . $email_domain;


#########################################################################################################

## CVE DATA COLLECTED
my $cvedata = $cfg->param("cve_data");

## IP ADDRESS MAPPINGS TO BE INCLUDED IN THE TICKET DESCRIPTION
my $ipmappings = $cfg->param("ip_mappings");

## REQUEST AREA FOR SD TICKET
my $request_area = $cfg->param("request_area");





##############  MISCELLANEOUS VARIABLES  ####################################

my $starttime = scalar localtime;
my $sourcefolder = getcwd;
my $ipcount = 0;
my $pcivulncount = 0;
my $allticketcounter = 0;
my %topvulnhosts_ticketurls;
my %vulntickets_urls;
my %vulnhosts_ticketurls;
my %qid_perregion;
my %thirdqid_perregion;
my %fourthqid_perregion;
my %ip_vulnentries; 
my %thirdip_vulnentries;
my %fourthip_vulnentries;
my %region_ticketurls;
my @attachments;
my %lastregion;
my %thirdregion;
my %fourthregion;
my %lastqid_perregion;
my %lastip_vulnentries;
my %external_mappings;
my %vip_mappings;
my %cve_data;
my %ip_regionmap : shared;
my %savedxmlfiles;
my %wantedvulns;
my %createonly_tickets;
my %nonpci_tickets;
my $ua = new LWP::UserAgent(keep_alive => 1);
my $async = HTTP::Async->new (('proxy_host' => '127.0.0.1', 'proxy_port' => '9090', 'slots' => '20'));
my %vulns_impact = (1 => 'Emergency', 2 => 'Critical', 3 => 'Major', 4 => 'Minor');

### ENTER TWO-DIGIT MONTH EQUIVALENT HERE TO PROCESS ONLY SCAN RESULTS FOR THAT MONTH
my $monthfilter = $cfg->param("month_filter");

$sourcefolder .= '/';
chomp $sourcefolder;


################## ASSET GROUP SELECTION ##########################


print "\n\nGetting the list of asset groups in Qualys...\n\n";
my ($qualysthread) = threads->create('get_asset_groups');
my (%asset_groups) = $qualysthread->join();


foreach my $index (sort {$a<=>$b} keys %asset_groups){   
   foreach my $region (keys %{$asset_groups{$index}}){
         print "($index) $region\n";
   }
   
}

####################################################################



if (!defined $selectedregions or $selectedregions eq ''){   
   $selectedregions = $cfg->param("selected_regions");
   unless (!ref ($selectedregions)){
      print "\n\nSelect which scan result(s) to process:[ALL] "; 
      ReadMode('normal');
      $selectedregions = ReadLine(0);  
   }
}

   chomp $selectedregions;
   $selectedregions =~ s/\D+/ /g;
      
###### PROCESS ALL REGIONS BY DEFAULT (PCI ONLY) 

   $selectedregions = '' if ($selectedregions =~ /^\s+$/);   
   $selectedregions = join(' ', keys %asset_groups) if ($selectedregions eq '');

########################################################################
######################## PROCESS NON-PCI OPTION ########################


if (!defined $process_nonpci or $process_nonpci eq ''){   
       $process_nonpci = $cfg->param("process_nonpci");
       unless (! ref($process_nonpci)){
          print"\nWould you like to process non-PCI vulnerabilities?[n] ";
          ReadMode('normal');
          $process_nonpci = ReadLine(0);  
       }
}



   chomp $process_nonpci;
   $process_nonpci = 'n' if $process_nonpci eq '';

   if ((lc($process_nonpci)) eq 'n' || $process_nonpci eq '' || (lc($process_nonpci)) eq 'no'){
      $process_nonpci = 'no';
   }elsif((lc($process_nonpci)) eq 'y' || (lc($process_nonpci)) eq 'yes'){
      $process_nonpci = 'yes';
   }else{
       say "\nInvalid selection " . "\"$process_nonpci\". Defaulting to \'no\'.\n";
       $process_nonpci = 'no';
   }

########################################################################
############### PROCESS MODE SELECTION #################################


unless (! ref ($process_mode)){
       print "\n\n\n1.) Process scheduled scan\n2.) Process adhoc scan (no tickets)\n\n\nWhat do you want to do?[1] ";
       ReadMode('normal');
       $process_mode = ReadLine(0);
}
   chomp $process_mode;
   $process_mode = 1 if $process_mode eq '';
   
if ($process_mode == 1){
   $process_anontargets = 'no';
   say "\n\n\nDownloading scheduled scan results...\n\n";
}elsif($process_mode == 2){
   $process_anontargets = 'yes';
   print "\nEnter Qualys login used to run the scan: ";
   ReadMode('normal');
   $scanner_account = ReadLine(0);
   chomp $scanner_account;
   say "\n\n\n              *****************************************************************************";
   say       "              **                                                                         **";
   say       "              **                              W A R N I N G                              **";
   say       "              **                                                                         **";
   say       "              **    If the hosts you are validating the remediation of do not belong     **";
   say       "              **    to the asset group you selected above, the script will not see any   **";
   say       "              **    scan result. You must add those IPs into an existing asset group     **";
   say       "              **    or create a new one and add them to it.                              **";
   say       "              **                                                                         **";
   say       "              *****************************************************************************\n\n";
   print "\nHit enter to continue ";
                  while (<STDIN>){
	             chomp;	
	             last if $_ eq '';
                  }
   say "\n\n\nDownloading adhoc scan results...\n\n";

}else{
   say "\nInvalid selection " . "\"$process_mode\". Defaulting to scheduled scan.\n";
   say "\n\n\nDownloading scheduled scan results...\n\n";

}



########################################################################
#### DOWNLOAD XML SCAN RESULT FOR EACH SELECTED ASSET GROUP.


my %choices;
my @currentscanresult;
my @secondscanresult;
my @thirdscanresult;
my @fourthscanresult;

@choices{ split /\s+/, $selectedregions } = ();
my @exploadthreads;


foreach my $index(sort {$a<=>$b} keys %choices){ 
     foreach my $region (keys %{$asset_groups{$index}}){ 

### To build a quick hash lookup table of IP-to-Region mappings, each target range in an asset group is exploaded into individual IPs and written to text files placed in region_ip_block config param  
        my $exploadthread = threads->create('expload_iprange', $asset_groups{$index}{$region}{IPs}, $region, $asset_groups{$index}{$region}{LAST_UPDATE}); 
        push @exploadthreads, $exploadthread;
        print "\n$region\n"; 
        my $targets = join (',' , @{$asset_groups{$index}{$region}{IPs}});
### Now we get the scan results here
        my (@scanresults) = get_scanresult($targets, \$region);
        if (scalar @scanresults == 0){
           if (scalar keys %choices == 1){
              print "\n\n\nNo scan result found. Exiting...\n\n\n";
              exit;
           }else{
              print "\n******* No scan result found for $region. Skipping... *******\n\n\n";
              next;
          }       
        }

        $region_ticketurls{$region}[7] = $targets;  #SAVE THE TARGET IP ADDRESS RANGES HERE TO BE WRITTEN IN EXCEL SPREADSHEETS
        push @currentscanresult, $scanresults[0];
        push @secondscanresult, $scanresults[1] if (defined $scanresults[1] && $scanresults[1] ne '');
        push @thirdscanresult, $scanresults[2] if (defined $scanresults[2] &&  $scanresults[2] ne '');
        push @fourthscanresult, $scanresults[3] if (defined $scanresults[3] && $scanresults[3] ne '');
        $region_ticketurls{$region}[3]{'scanref'} = $scanresults[4] if defined $scanresults[4];
        $region_ticketurls{$region}[3]{'launchdate'} = $scanresults[5] if defined $scanresults[5];
        $lastregion{$region}[3]{'launchdate'} = $scanresults[6] if defined $scanresults[6];
        $thirdregion{$region}[3]{'launchdate'} = $scanresults[7] if defined $scanresults[7];
        $fourthregion{$region}[3]{'launchdate'} = $scanresults[8] if defined $scanresults[8];

     }
}
 
 

############################################################################### 
### Just returning from our IP-to-Region mapping threaad

say "\n\nExpanding IP address range...";
foreach (@exploadthreads){
   $_->join();
}



###############################################################################
##################### EXTRACT  IP-TO-CVE MAPPINGS #############################

say "Extracting IP-to-CVE mappings...";

if (!-e $cvedata){
   print "LIST OF IP ADDRESS TO CVE MAPPINGS ($cvedata) MISSING. EXITING..\n";
   exit;
}
my $cvedataexcel = Spreadsheet::XLSX -> new ($cvedata);
(my $cveroot) = $cvedata =~ /^(\/\/.*?)\//;

foreach my $cvedatasheet (@{$cvedataexcel -> {Worksheet}}) {
     
  $cvedatasheet -> {MaxRow} ||= $cvedatasheet -> {MinRow};
  foreach my $row (0 .. $cvedatasheet -> {MaxRow}) {
     $cvedatasheet -> {MaxCol} ||= $cvedatasheet -> {MinCol};
     if (!defined $cvedatasheet -> {Cells} [$row] [0] -> {Val} && !defined $cvedatasheet -> {Cells} [$row] [1] -> {Val}){
        next;
     }else{
        next if !defined $cvedatasheet -> {Cells} [$row] [5] -> {Val};
     }
     my $ip = $cvedatasheet -> {Cells} [$row] [1] -> {Val};
     my $hostname = $cvedatasheet -> {Cells} [$row] [0] -> {Val};
     my $cve = $cvedatasheet -> {Cells} [$row] [5] -> {Val};     
     
     if (!defined $ip || $ip !~ /\d+\.\d+\.\d+\.\d+/){
        if ((defined $hostname && $hostname ne '') && (defined $cve && $cve ne '')){
          $hostname =~ s/\s+//g;
          my (@info) = gethostbyname($hostname);
          next if !defined $info[4];
          print "Resolving $hostname == " if $debug eq 'yes';
          my ($a,$b,$c,$d) =  unpack('C4',$info[4]);
          $ip = "$a.$b.$c.$d";
          say $ip if $debug eq 'yes';
        }else{
          next;
        }
     }      
     ($ip) = $ip =~ /\d+\.\d+\.\d+\.\d+/g;
     my @cve = $cve =~ /(CVE-\d+-\d+|CAN-\d+-\d+)/g;   
     for (@cve){
        $cve_data{$ip}{$_} = undef;
     }                    
  }
}



###############################################################################
##################### EXTRACT EXTERNAL_IP-to-VIP-to-SERVER_IP MAPPINGS #############################

say "Extracting External-VIP-Server IP mappings...";

if (!-e $ipmappings){
   print "LIST OF IP ADDRESS MAPPINGS ($ipmappings) MISSING. EXITING..\n";
   exit;
}


my $ipmappingsexcel = Spreadsheet::XLSX -> new ($ipmappings);
(my $mappingsroot) = $ipmappings =~ /^(\/\/.*?)\//;

#print "\nExtracting IP Address mappings (\"$mappingsroot.../Qualys CA Service Desk Integration/ip_mappings.xlsx\")...\n";

foreach my $ipmappingssheet (@{$ipmappingsexcel -> {Worksheet}}) {
  
  $ipmappingssheet -> {MaxRow} ||= $ipmappingssheet -> {MinRow};
  foreach my $row (0 .. $ipmappingssheet -> {MaxRow}) {
     $ipmappingssheet -> {MaxCol} ||= $ipmappingssheet -> {MinCol};
     next if not defined $ipmappingssheet -> {Cells} [$row] [0] -> {Val};
     my $activeip = $ipmappingssheet -> {Cells} [$row] [0] -> {Val}; 
     $activeip =~ s/\s+//g;
     chomp $activeip;
     next unless $activeip =~ /^\d+\.\d+\.\d+\.\d+$/; 
     
     my $vip = $ipmappingssheet -> {Cells} [$row] [1] -> {Val} || 'Not Available';
     $vip =~ s/\s+//g;
     my $serversip = $ipmappingssheet -> {Cells} [$row] [2] -> {Val} || 'Not Available';     
     $serversip =~ s/^\s+//;
     chomp ($vip, $serversip);     
     $serversip = join (',', split(/\s+/, $serversip));
     $external_mappings{$activeip} = "VIP: $vip" . ' ' . "SERVER IP: $serversip";
     $vip_mappings{$vip} = "EXTERNAL: $activeip" . ' ' . "SERVER IP: $serversip";
     
           
  }

}



##############################################################################################
### SEARCH THE LATEST SUBMITTED TICKET SPREADSHEET FOR EVERY REGION

my $ticketspath = $cfg->param("tickets_path");

unless (-e $ticketspath && -d $ticketspath){
  print "MISSING SUBMITTED TICKETS FOLDER. CREATING ONE...\n";
  mkdir $ticketspath or (die "Unable to create submitted tickets folder. Check your permission on $ticketspath\n");
}


say "Searching existing tickets...";

my %findopts = (follow_skip => 2, wanted => \&wanted);
find(\%findopts, $ticketspath);
sub wanted {
   $| = 1;
     if (! -d $_ && $_ !~ /tmp/ && $_ =~ /^\d+/){
        
         (my $region) = $_ =~ /-\s(.*)_/;
         print ".";
         if (defined $region_ticketurls{$region}){ 
               my $tempfile = quotemeta($_);  
              (my $date) = $_ =~ /^(\d+)\s-/;
               my $newdate = convert_date($date, 'mmddyyyy');
### IF latest_result_date IS SPECIFIED, WE'LL EXCLUDE SPREADSHEETS BEYOND THIS DATE
                my $dateupperlimit;
                my $newdateupperlimit;
                ($dateupperlimit = $target_date) =~ s/-//g if defined $target_date;              
                if (defined $dateupperlimit && !ref $dateupperlimit){
                    $newdateupperlimit = convert_date($dateupperlimit, 'yyyymmdd');
                    if ($newdate > $newdateupperlimit){
                        return;
                    }
                }

 
### NOW WE START SEARCHING FOR THE LATEST SPREADSHEETS HERE
               my $fullfilename = $File::Find::name;                
               (my $filedir) = $fullfilename =~ /^(.*)$tempfile/;               
               
        if ($_ =~ /tickets/){       
               
               if (!defined $region_ticketurls{$region}[4]{fullfile}){  
                    $region_ticketurls{$region}[4]{fullfile} = $fullfilename;
                    $region_ticketurls{$region}[4]{filedir} = $filedir; 
                    $region_ticketurls{$region}[4]{file} = $_;      
               }else{
                    (my $storeddate) = $region_ticketurls{$region}[4]{fullfile} =~ /\/(\d+)\s\-/;
                    if (convert_date($date, 'mmddyyyy') > convert_date($storeddate, 'mmddyyyy')){ 
                        $region_ticketurls{$region}[4]{fullfile} = $fullfilename;
                        $region_ticketurls{$region}[4]{filedir} = $filedir;
                        $region_ticketurls{$region}[4]{file} = $_;
                        
                     }     
                }
### WE ALSO SEARCH FOR THE LATEST ADHOC SPREADSHEETS IN CASE WE WANT TO EDIT IT INSTEAD OF THE MASTER SPREADSHEET WHEN OPTION 6 IS SELECTED
          }else{
             if (!defined $region_ticketurls{$region}[4]{adhocfullfile}){  
                    $region_ticketurls{$region}[4]{adhocfullfile} = $fullfilename;
                    $region_ticketurls{$region}[4]{adhocfiledir} = $filedir; 
                    $region_ticketurls{$region}[4]{adhocfile} = $_;      
               }else{
                    (my $storeddate) = $region_ticketurls{$region}[4]{adhocfullfile} =~ /\/(\d+)\s\-/;
                    if (convert_date($date, 'mmddyyyy') > convert_date($storeddate, 'mmddyyyy')){ 
                        $region_ticketurls{$region}[4]{adhocfullfile} = $fullfilename;
                        $region_ticketurls{$region}[4]{adhocfiledir} = $filedir;
                        $region_ticketurls{$region}[4]{adhocfile} = $_;
                        
                     }     
                }
          }    
                
                
                
          } 
      }
}

$| = 0;
print "\n";

### SUB FOR CONVERTING OUR DATES THAT str2time CAN UNDERSTAND AND CONVERT TO UNIX TIMESTAMPS

sub convert_date{
   my $date = shift;  
   my $format = shift;
   my ($month, $day, $year, $newdate);
   if ($format eq 'mmddyyyy'){ 
      $month = substr $date, 0, 2;
      $day = substr $date, 2, 2;
      $year = substr $date, 4, 4;
      $newdate = $month . '/' . $day . '/' . $year;
   }else{
      $month = substr $date, 4, 2;
      $day = substr $date, 6, 2;
      $year = substr $date, 0, 4;
      $newdate = $month . '/' . $day . '/' . $year;
   }
   
   return str2time($newdate);
}
###########################################################################################

### READ THE LATEST SUBMITTED TICKETS SPREADSHEETS AND EXTRACT THE EXISTING TICKETS SO THAT WHEN SCAN RESULTS ARE PROCESSED, WE WON'T CREATE DUPLICATE TICKETS

my %submittedtickets;

foreach my $region (keys %region_ticketurls){    
    my $latest = $region_ticketurls{$region}[4]; 
    if (defined $latest && scalar keys %$latest != 0){
       $submittedtickets{$region} = $latest;
    }else{
       next;
    }
}

my ($excelthread) = threads->create('read_excel',\%submittedtickets, 'master');
my (@readexcel) = $excelthread->join();
my %lastqid = %{$readexcel[0]};
%nonpci_tickets = %{$readexcel[2]};



###########################################################################################

### NOW WE EXTRACT THE XML RESULTS AND SAVE THE CONTENTS VIA SAVE_VULNS SUB
say "Extracting scan results...";

foreach my $xmlstring (@currentscanresult){ 
  my $parser = XML::LibXML->new();   
  my $xmlresult  = $parser->parse_file($$xmlstring);
  my $vulns = extract_fields($xmlresult, 'vulns', 'current'); 
  my $infos = extract_fields($xmlresult, 'infos', 'current');  
  my $practices = extract_fields($xmlresult, 'practices', 'current'); 
  my $services = extract_fields($xmlresult, 'services', 'current'); 
  save_vulns($vulns, $infos, $practices, $services);
}



### WE ALSO EXTRACT THE LAST THREE SCAN RESULTS BUT ONLY GET THE STATS SO WE CAN ADD THEM TO SPREADSHEET AS HISTORICAL TREND
unless (scalar @secondscanresult == 0){
foreach my $secondxmlstring (@secondscanresult){ 
  my $secondparser = XML::LibXML->new();   
  my $secondxmlresult  = $secondparser->parse_file($$secondxmlstring);
  my $secondvulns = extract_fields($secondxmlresult, 'vulns', 'last');
  my $secondinfos = extract_fields($secondxmlresult, 'infos', 'last');
  my $secondpractices = extract_fields($secondxmlresult, 'practices', 'last');
  my $secondservices = extract_fields($secondxmlresult, 'services', 'last'); 
  save_lastvulns($secondvulns, $secondinfos, $secondpractices);

}
}


unless (scalar @thirdscanresult == 0){
foreach my $thirdxmlstring (@thirdscanresult){ 
  my $thirdparser = XML::LibXML->new();   
  my $thirdxmlresult  = $thirdparser->parse_file($$thirdxmlstring);
  my $thirdvulns = extract_fields($thirdxmlresult, 'vulns', 'last');
  my $thirdinfos = extract_fields($thirdxmlresult, 'infos', 'last');
  my $thirdpractices = extract_fields($thirdxmlresult, 'practices', 'last');
  my $thirdservices = extract_fields($thirdxmlresult, 'services', 'last'); 
  save_thirdvulns($thirdvulns, $thirdinfos, $thirdpractices);

}
}

unless (scalar @fourthscanresult == 0){
foreach my $fourthxmlstring (@fourthscanresult){ 
  my $fourthparser = XML::LibXML->new();   
  my $fourthxmlresult  = $fourthparser->parse_file($$fourthxmlstring);
  my $fourthvulns = extract_fields($fourthxmlresult, 'vulns', 'last');
  my $fourthinfos = extract_fields($fourthxmlresult, 'infos', 'last');
  my $fourthpractices = extract_fields($fourthxmlresult, 'practices', 'last');
  my $fourthservices = extract_fields($fourthxmlresult, 'services', 'last'); 
  save_fourthvulns($fourthvulns, $fourthinfos, $fourthpractices);

}
}

###########################################################################################

##########   SCAN RESULT PROCESSING SELECTIONS  ###################
### WE COUNT THE NUMBER OF VULNERABILITIES HERE BASED ON IMPACT SO THAT WE CAN PRESENT THEM TO THE USER LATER


foreach my $region (keys %region_ticketurls){
   
   my $selectedvulns = $origselectedvulns;   
   $selectedvulns = join (' ', @{$selectedvulns}) if ref($selectedvulns);
   if (!defined $selectedvulns or $selectedvulns eq ''){
     $selectedvulns = $cfg->param("selected_vulns");
   }
      
    my $latest = $region_ticketurls{$region}[4];    

### COUNT THE TOTAL VULNERABILITIES

    my ($totalvuln, $emergencyvuln, $criticalvuln, $majorvuln, $minorvuln, 
        $totaltickets, $emergencytickets, $criticaltickets, $majortickets, $minortickets);
        
    my ($lasttotalvuln, $lastemergencyvuln, $lastcriticalvuln, $lastmajorvuln, $lastminorvuln, 
        $thirdtotalvuln, $thirdemergencyvuln, $thirdcriticalvuln, $thirdmajorvuln, $thirdminorvuln,  
        $fourthtotalvuln, $fourthemergencyvuln, $fourthcriticalvuln, $fourthmajorvuln, $fourthminorvuln);
        
    $totalvuln = $emergencyvuln = $criticalvuln = $majorvuln = $minorvuln = 0;    
    $totaltickets = $emergencytickets = $criticaltickets = $majortickets = $minortickets = 0;   
    $lasttotalvuln = $lastemergencyvuln = $lastcriticalvuln = $lastmajorvuln = $lastminorvuln = 0;
    $thirdtotalvuln = $thirdemergencyvuln = $thirdcriticalvuln = $thirdmajorvuln = $thirdminorvuln = 0;
    $fourthtotalvuln = $fourthemergencyvuln = $fourthcriticalvuln = $fourthmajorvuln = $fourthminorvuln = 0;     
    $region_ticketurls{$region}[10]{newemergency} = $region_ticketurls{$region}[10]{newcritical} = $region_ticketurls{$region}[10]{newmajor} = $region_ticketurls{$region}[10]{newminor} = 0;  
 
    for my $ip (keys %ip_vulnentries){
           foreach (@{$ip_vulnentries{$ip}}){
                my $ip_port = $$_[0] . ($$_[15] =~ /\d+/?":$$_[15]":'');  
                next unless $ip_regionmap{$ip} eq $region;
                ++$totalvuln;

                if (get_impact($$_[8], 'impact', $$_[18]) eq 'Emergency'){
                   ++$emergencyvuln;
                   ++$emergencytickets if defined $lastqid{$$_[14]}{$ip_port};
                   next;
                }
                if (get_impact($$_[8], 'impact', $$_[18]) eq 'Critical'){
                   ++$criticalvuln;
                   ++$criticaltickets if defined $lastqid{$$_[14]}{$ip_port};
                   next;
                }
                if (get_impact($$_[8], 'impact', $$_[18]) eq 'Major'){
                   ++$majorvuln;
                   ++$majortickets if defined $lastqid{$$_[14]}{$ip_port};
                   next;
                }
                if (get_impact($$_[8], 'impact', $$_[18]) eq 'Minor'){
                   ++$minorvuln;
                   ++$minortickets if defined $lastqid{$$_[14]}{$ip_port};
                   next;
                } 
           } 
      }
      $region_ticketurls{$region}[9]{total} = $totalvuln;
      $region_ticketurls{$region}[9]{emergency} = $emergencyvuln;
      $region_ticketurls{$region}[9]{critical} = $criticalvuln;
      $region_ticketurls{$region}[9]{major} = $majorvuln;
      $region_ticketurls{$region}[9]{minor} = $minorvuln;
      
      $region_ticketurls{$region}[10]{emergency} = $emergencytickets;
      $region_ticketurls{$region}[10]{critical} = $criticaltickets;
      $region_ticketurls{$region}[10]{major} = $majortickets;
      $region_ticketurls{$region}[10]{minor} = $minortickets;
      $totalvuln = $emergencyvuln = $criticalvuln = $majorvuln = $minorvuln = $totaltickets = $emergencytickets = $criticaltickets = $majortickets = $minortickets = 0;


unless (scalar keys %lastip_vulnentries == 0){
      for my $ip (keys %lastip_vulnentries){
           foreach (@{$lastip_vulnentries{$ip}}){
             next unless $ip_regionmap{$ip} eq $region;
             ++$lasttotalvuln;
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Emergency'){
                ++$lastemergencyvuln;
                next;             
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Critical'){
                ++$lastcriticalvuln;
                next;
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Major'){
                ++$lastmajorvuln;
                next;
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Minor'){
                ++$lastminorvuln;
                next;
             }
           } 
      }
}
      $lastregion{$region}[4]{total} = $lasttotalvuln;
      $lastregion{$region}[4]{emergency} = $lastemergencyvuln;
      $lastregion{$region}[4]{critical} = $lastcriticalvuln;
      $lastregion{$region}[4]{major} = $lastmajorvuln;
      $lastregion{$region}[4]{minor} = $lastminorvuln;
      $lasttotalvuln = $lastemergencyvuln = $lastcriticalvuln = $lastmajorvuln = $lastminorvuln = 0;
  
unless (scalar keys %thirdip_vulnentries == 0){      
      for my $ip (keys %thirdip_vulnentries){
           foreach (@{$thirdip_vulnentries{$ip}}){
             next unless $ip_regionmap{$ip} eq $region;
             ++$thirdtotalvuln;
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Emergency'){
                ++$thirdemergencyvuln;
                next;
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Critical'){
                ++$thirdcriticalvuln;
                next;
             } 
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Major'){
                ++$thirdmajorvuln; 
                next;
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Minor'){
                 ++$thirdminorvuln;
                 next;
             }
           } 
      }
}
      $thirdregion{$region}[4]{total} = $thirdtotalvuln;
      $thirdregion{$region}[4]{emergency} = $thirdemergencyvuln;
      $thirdregion{$region}[4]{critical} = $thirdcriticalvuln;
      $thirdregion{$region}[4]{major} = $thirdmajorvuln;
      $thirdregion{$region}[4]{minor} = $thirdminorvuln;
      $thirdtotalvuln = $thirdemergencyvuln = $thirdcriticalvuln = $thirdmajorvuln = $thirdminorvuln = 0; 
      

unless (scalar keys %fourthip_vulnentries == 0){            
      for my $ip (keys %fourthip_vulnentries){
           foreach (@{$fourthip_vulnentries{$ip}}){
             next unless $ip_regionmap{$ip} eq $region;
             ++$fourthtotalvuln;
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Emergency'){
                ++$fourthemergencyvuln;
                next;
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Critical'){
                ++$fourthcriticalvuln;
                next;
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Major'){
                ++$fourthmajorvuln;
                next;
             }
             if (get_impact($$_[0], 'impact', $$_[1]) eq 'Minor'){
                ++$fourthminorvuln;
                next;
             }
           } 
      }
      
}
      $fourthregion{$region}[4]{total} = $fourthtotalvuln;
      $fourthregion{$region}[4]{emergency} = $fourthemergencyvuln;
      $fourthregion{$region}[4]{critical} = $fourthcriticalvuln;
      $fourthregion{$region}[4]{major} = $fourthmajorvuln;
      $fourthregion{$region}[4]{minor} = $fourthminorvuln;
      $fourthtotalvuln = $fourthemergencyvuln = $fourthcriticalvuln = $fourthmajorvuln = $fourthminorvuln = 0;  


 


#############################


### NO EXCEL SUBMITTED TICKETS FOUND
           unless ($process_mode == 2){
               print "\nWARNING: No existing tickets for $region. $region_ticketurls{$region}[9]{total} new tickets will be created.\n\n" if not defined $latest;
           }
           
           if (defined $latest){
              if ($region_ticketurls{$region}[9]{total} == 0){
                 say $region, "\n";
              }else{
                  print "\nWARNING: $region_ticketurls{$region}[9]{total} issues are still unresolved for $region.\n\n" unless $region_ticketurls{$region}[9]{total} == 0;
              }
           }
           
### DISPLAY THE OPTIONS TO THE USER WITH CORRESPONDING VULNERABILITY COUNTS
       
           say "1) EMERGENCY ($region_ticketurls{$region}[9]{emergency})";
           say "2) CRITICAL ($region_ticketurls{$region}[9]{critical})";
           say "3) MAJOR ($region_ticketurls{$region}[9]{major})";
           say "4) MINOR ($region_ticketurls{$region}[9]{minor})";
           my $all = $region_ticketurls{$region}[9]{minor} + $region_ticketurls{$region}[9]{major}+ $region_ticketurls{$region}[9]{critical} + $region_ticketurls{$region}[9]{emergency};
           say "5) ALL ($all)";
### ONLY SHOW OPTION 6 & 7 IF PROCESS SCHEDULED  
         
       if ($process_mode == 1){ 
           say "6) Select manually.\n"; 
           say "7) (No tickets. Just update the list)\n";
           print "Select which vulns to process:[7] ";
           
           
           if ($all < 1){
              $selectedvulns = 7; 
           }else{
              unless (!ref($selectedvulns)){
                  ReadMode('normal');     
                  $selectedvulns = ReadLine(0);
              }
              
           }
           
           
           chomp $selectedvulns if defined $selectedvulns; 
           $selectedvulns =~ s/\D+/ /g;
           $selectedvulns = '' if ($selectedvulns =~ /^\s+$/); 
           if ($selectedvulns eq '') {
                $selectedvulns = 7;
           }
### DEFAULT TO OPTION 7 IF PROCESS ADHOC  
                              
      }else{
           $selectedvulns = 7;
      }


### DOWNLOAD AND OPEN SUBMITTED TICKET FOR EDITING IF OPTION 6 IS SELECTED

            if (defined $latest && $selectedvulns == 6){
               
               my $edit_selection;
               
### LET THE USER CHOOSE TO EDIT WHETHER THE MASTER SPREADSHEET OR AN ADHOC SPREADSHEET (GENERATED BY SELECTING process-mode 2).               
               if (defined $$latest{adhocfile}){
                  print "\n\n\n1.) Select from " . $$latest{file} . "\n2.) Select from ". $$latest{adhocfile} . "\n\n\nWhat do you want to do?[1] ";
                  ReadMode('normal');
                  $edit_selection = ReadLine(0);
                  chomp $edit_selection;
                  $edit_selection = 1 if $edit_selection eq '';
               }else{
                  $edit_selection = 1;
               } 
                                             
                     say "\n\nCreating a local copy of " . $$latest{file} . "..." if ($edit_selection == 1);
                     copy($$latest{fullfile}, $$latest{file}) if ($edit_selection == 1);
                     unless (!defined $$latest{adhocfile}){
                         say "\n\nCreating a local copy of " . $$latest{adhocfile} . "..." if ($edit_selection == 2);
                         copy($$latest{adhocfullfile}, $$latest{adhocfile}) if ($edit_selection == 2);
                     }
                     say "Opening " . ($edit_selection == 1?$$latest{file}:$$latest{adhocfile}) . "...\n\n\n\n\nEnter \"yes\" or the assignee group on the column \"Create SD Ticket?\". Save and close when done.";
                     print "\nHit enter to continue ";
                     while (<STDIN>){
	                chomp;	
	                last if $_ eq '';
                     }
                     my $to_edit;
                     if ($edit_selection == 1){
                        $to_edit = $$latest{file};
                      }else{
                         $to_edit = $$latest{adhocfile};
                      }
### OPEN THE SELECTED SPREADSHEET FOR EDITING.                      
                     system("$to_edit");
                     sleep 3;
### SAVE THE EDITED SPREADSHEET
                     say "\n\nCopying $$latest{file} to $$latest{fullfile} ..." if ($edit_selection == 1);                   
                     copy($$latest{file}, $$latest{fullfile}) or die "UNABLE TO UPLOAD EDITED LIST. CHECK FILE PERMISSION." if ($edit_selection == 1);
                     say "\n\nCopying $$latest{adhocfile} to $$latest{adhocfullfile} ..." if ($edit_selection != 1);                   
                     copy($$latest{adhocfile}, $$latest{adhocfullfile}) or die "UNABLE TO UPLOAD EDITED LIST. CHECK FILE PERMISSION." if ($edit_selection != 1);
                     say "Done.\n\n";
                 
### THEN RE-READ THE EDITED EXCEL AND LOOK FOR VULNS WITH ENTRIES IN "CREATE SD TICKET?" COLUMN
                  my ($selectexcel) = threads->create('read_excel',\%submittedtickets, ($edit_selection == 1?'master':'adhoc'));
                  my (@selectreadexcel) = $selectexcel->join();
                  #%lastqid = %{$selectreadexcel[0]};
                  %createonly_tickets = %{$selectreadexcel[1]};
                  
                                    
            } 
            
### PROCESS ALL VULN IMPACTS (1-4) IF OPTION 7 IS SELECTED BUT DO NOT CREATE TICKET, WE JUST WANT TO GENERATE THE SPREADSHEETS AND UPDATE THE TICKET STATUS

           if ($selectedvulns == 7){
                print "\n";
                $selectedvulns = "1 2 3 4";
                $region_ticketurls{$region}[6] = 'yes'; #FLAG FOR DO NOT CREATE TICKET               
           }else{
              
### PROCESS ALL VULN IMPACTS (1-4) IF OPTION 5 IS SELECTED

                if ($selectedvulns == 5){
                   $selectedvulns = "1 2 3 4";
                   $region_ticketurls{$region}[6] = 'no';

### PROCESS ONLY TICKETS MARKED WITH 'YES'

                }elsif($selectedvulns == 6){
                   $selectedvulns = "1 2 3 4";
                   $region_ticketurls{$region}[6] = 'no';
                   $region_ticketurls{$region}[8] = 'yes'; #FLAG FOR CREATE TICKET ONLY FOR MARKED VULNS  
     
                }else{
### PROCESS WHATEVER IMPACT (1-4) IS/ARE SELECTED

                     $region_ticketurls{$region}[6] = 'no';
                }
           }        
         
             my %selectedvulns; 
             @selectedvulns{ split /\s+/, $selectedvulns } = ();
             for my $index (keys %selectedvulns){
                 delete $selectedvulns{$index} unless exists $vulns_impact{$index};
                 $selectedvulns{$index} = $vulns_impact{$index} if exists $vulns_impact{$index};
             }
             %selectedvulns = reverse %selectedvulns;
             $region_ticketurls{$region}[5] = \%selectedvulns;
}




####################################################################################
### NOW WE START CREATING TICKETS HERE



my $vulncount = 0;

#print "\nCreating the needed SD tickets...\n\n" unless $noticket eq 'yes';

my $asyncsid = get_sid(\$ua, \$username, \$password);
my $marker = 'no';
my $queuecounter = 0;

for my $IPADD (keys %ip_vulnentries){
       my $region = $ip_regionmap{$IPADD};
       ++$ipcount;
       my $regionticketurlid = '';
       my $regionticket = ($region_ticketurls{$region}[0][0] || '');
       $region_ticketurls{$region}[0] = [$regionticket, $regionticketurlid]; 
       my $ipticket = '';
       my $ipticketurlid = '';
       chomp $ipticketurlid;
       push (@{$vulnhosts_ticketurls{$IPADD}[0]}, $ipticketurlid); 

         
       foreach (@{$ip_vulnentries{$IPADD}}){
            my $qidkey = $$_[0] . ($$_[15] =~ /\d+/?":$$_[15]":'');
            ++$vulncount;
            my ($vulnticket, $vulnticketurlid); 

#1.) TEST IF TICKET EXISTS IN THE SUBMITTED TICKET SPREADSHEET AND ALREADY HAS A TICKET, THEN EXTRACT THE TICKET NO. AND URLID
            if (defined $lastqid{$$_[14]} && defined $lastqid{$$_[14]}{$qidkey}){
                      print "Ticket exists for QID:$$_[14] - $qidkey. Skipping...\n" if $debug eq 'yes'; 
                      foreach my $ticket (keys %{$lastqid{$$_[14]}{$qidkey}}){        
                           $vulnticket = $ticket;
                           $vulnticketurlid = $lastqid{$$_[14]}{$qidkey}{$ticket};
                           ($vulnticketurlid) = $vulnticketurlid =~ /id=(\d+)$/;
                      }                                                                                                     
             }else{ 
                say "THERE IS NO EXISTING TICKET. TESTING IF IT IS FILTERED" if $debug eq 'yes';
#2.) IF NOT, TEST IF IT IS A FILTERED VULN, E.G., IF MAJOR AND EMERGENCY ONLY WERE SELECTED, THEN SKIP
                  if (filter_vuln($$_[8], $$_[18], $region_ticketurls{$region}[5]) eq 'yes'){
                     say "YES IT IS FILTERED. SKIPPING" if $debug eq 'yes';
                     next;
                  }                
                  
#3.) TEST IF #7 WAS SELECTED, (NO TICKETS, JUST UPDATE STATUS)                   
                  if (defined $region_ticketurls{$ip_regionmap{$IPADD}}[6] && $region_ticketurls{$ip_regionmap{$IPADD}}[6] eq 'yes'){ 
                     say "SEVEN SELECTED" if $debug eq 'yes';
#            if ($process_mode == 1){
                       $vulnticket = '(no ticket yet)';
#                     }else{
#                       $vulnticket = '';
#                     }
                       $vulnticketurlid = '';
                  }else{ 
#4.) IF NOT, TEST IF #6 WAS SELECTED (SELECT MANUALLY) 
                           
                          if (defined $region_ticketurls{$region}[8] && $region_ticketurls{$region}[8] eq 'yes'){
                            say "YES SIX WAS SELECTED" if $debug eq 'yes';
#5.) CREATE TICKET IF THERE IS A YES IN CREATE TICKET? COLUMN

                             if (defined $createonly_tickets{$$_[14]}{$qidkey} && (lc($createonly_tickets{$$_[14]}{$qidkey})) eq 'yes'){
                                say "YES THERE IS A YES. NOW CREATING TICKET." if $debug eq 'yes';
                                say "Submitting SD ticket for $qidkey - QID:$$_[14]..." if $debug eq 'yes';
                                ($vulnticket, $vulnticketurlid) = create_ticket('child', $ipticket, $_);
                                 update_newtickets_count($$_[8], $$_[18], $region);                        
                                
                             }elsif (defined $createonly_tickets{$$_[14]}{$qidkey}){  
                                
                                say "YES THERE IS NO YES BUT A GROUP NAME. CREATING TICKET AND ASSIGNING TO THAT GROUP" if $debug eq 'yes';
                                
                                ($vulnticket, $vulnticketurlid) = create_ticket('child', $ipticket, $_, $createonly_tickets{$$_[14]}{$qidkey});
                                update_newtickets_count($$_[8], $$_[18], $region);                        
     
                             }else{ 
                                say "THERE IS NEITHER YES NOR GROUP" if $debug eq 'yes';
                                $qid_perregion{$region}{$$_[14]}[1]{$qidkey}[0] = '(no ticket yet)';
                                $qid_perregion{$region}{$$_[14]}[1]{$qidkey}[1] = '';
                                
                                
#6.) ELSE IF THERE IS NO YES IN THE LAST COLUMN, SKIP CREATING TICKET                       
                                  next;
                             }
                          }else{
                             say "NO MANUAL SELECTION. JUST CREATING TICKET" if $debug eq 'yes';
                             
#7.) IF IT IS NOT SELECT MANUALLY, THEN JUST CREATE THE TICKET.
                             ($vulnticket, $vulnticketurlid) = create_ticket('child', $ipticket, $_);
                              update_newtickets_count($$_[8], $$_[18], $region);                        

                                   
                          }
                       
                  }   
                    ++$pcivulncount; 
              }

             chomp $vulnticketurlid if defined $vulnticketurlid;
              
             if (defined $vulnticket){
                say "FINALLY THERE IS VULNTICKET. SAVING" if $debug eq 'yes';
                 $qid_perregion{$region}{$$_[14]}[1]{$qidkey}[0] = $vulnticket;
                 $qid_perregion{$region}{$$_[14]}[1]{$qidkey}[1] = $vulnticketurlid;
                 say "VULNTICKETURL IS $vulnticketurlid" if $debug eq 'yes';

             }else{
                say "FINALLY NO TICKET YET" if $debug eq 'yes';
                $qid_perregion{$region}{$$_[14]}[1]{$qidkey}[0] = '(no ticket yet)';
                $qid_perregion{$region}{$$_[14]}[1]{$qidkey}[1] = '';
             }
        
             if ((defined $vulnticketurlid && $vulnticketurlid ne '')){  
                say "QUEUEING $vulnticketurlid FOR TICKET INFO FOR $qidkey" if $debug eq 'yes';
                
                unless ($update_status eq 'no'){
                  $qid_perregion{$region}{$$_[14]}[1]{$qidkey}[2] = queue_request(\$vulnticketurlid, $asyncsid, \$async);
               }
             }
             

           

             $vulntickets_urls{$vulnticket} = $vulnticketurlid;
             push (@{$vulnhosts_ticketurls{$IPADD}[1]}, $vulnticket); 
    }       
    $topvulnhosts_ticketurls{$IPADD} = [$vulncount, $ipticketurlid];
    $vulncount = 0; 

}   


### SUB FOR UPDATING THE COUNT OF NEW TICKETS          
sub update_newtickets_count{
   
   my $cvss_base = shift;
   my $correlation = shift;
   my $region = shift;
   ++$region_ticketurls{$region}[10]{newemergency} if get_impact($cvss_base, 'impact', $correlation) eq 'Emergency';
   ++$region_ticketurls{$region}[10]{newcritical} if get_impact($cvss_base, 'impact', $correlation) eq 'Critical';
   ++$region_ticketurls{$region}[10]{newmajor} if get_impact($cvss_base, 'impact', $correlation) eq 'Major';
   ++$region_ticketurls{$region}[10]{newminor} if get_impact($cvss_base, 'impact', $correlation) eq 'Minor'; 
   return;
}
        



#############################################################################################
#### GET MISC INFO FOR EACH SD TICKET (ASSIGNEE GROUP, STATUS, AGE) AND DISPLAY A PROGRESS BAR

    my %inforesponse;
    my $max = $async->total_count;
    
    
unless ($update_status eq 'no'){
 if ($max > 0){
    my $progress = Term::ProgressBar->new({name => "Retrieving ticket info ($max existing tickets)", count => $max, remove => 0, term_width => 100});
    $progress->minor(0);
    my $next_update = 0;
    my $responsecount = 0;
    while ( $async->not_empty ) {
            if ( my ($response, $id) = $async->wait_for_next_response() ) {
                $inforesponse{$id} = $response;
                ++$responsecount;
                $next_update = $progress->update($responsecount) if $responsecount >= $next_update;
           }
     }
     $progress->update($max) if $max >= $next_update;
}

}

my @regions;
my @regionimpacts;


###########################################################################################
###  ONCE TICKETS ARE CREATED, EXISTING ONES ARE NOTED, THE SPREADSHEETS ARE CREATED


foreach my $region (keys %region_ticketurls){
   chomp $region;
   next if not defined $region_ticketurls{$region}[3]{'launchdate'};  ### SKIP REGIONS WITH NO SCAN RESULTS
   (my $formatteddate = $region_ticketurls{$region}[3]{'launchdate'}) =~ s/\///g;
   my $scanref =   $region_ticketurls{$region}[3]{'scanref'};
   $scanref =~ s/scan\//adhoc scanref-/;
   
   my $regionfilename;
   if ($process_mode == 2){
      $regionfilename = $formatteddate . ' - ' . $region . '_' . "($scanref)"  . '.xlsx'; # adhoc spreadsheet
   }else{
      $regionfilename = $formatteddate . ' - ' . $region . '_tickets' . '.xlsx'; # main spreadsheet
   }
    
   my $attachfullpath = $sourcefolder . $regionfilename;
   my $uniqworkbook = Excel::Writer::XLSX->new($regionfilename);  
   push @attachments, $attachfullpath;
   my $uniqsheet   = $uniqworkbook->add_worksheet(); 
   my $lightgrey = $uniqworkbook->set_custom_color(55, 234, 234, 234);



# THIS WILL ADJUST THE EXCEL SHEETS' COLUMN BY EMULATING EXCEL'S RUNTIME AUTOFIT FEATURE

   $uniqsheet->add_write_handler(qr[\w], \&store_string_widths); 


### SET VARIOUS CELL FORMATTINGS HERE
   
   my $headingformat = $uniqworkbook->add_format( top => 1, color => 'white', bg_color => 'blue', bold => '1', align => 'center', top => '2', bottom => '2', left => '1', right => '1');
   my $qidformat = $uniqworkbook->add_format( bold => '1', bg_color => $lightgrey, top => '1', bottom => '1', left => '1', right => '1');
   my $format = $uniqworkbook->add_format( bold => '1', bg_color => 'yellow');
   my $format2 = $uniqworkbook->add_format(bold => '1', bg_color => 'cyan');
   my $format3 = $uniqworkbook->add_format(align => 'center');
   my $format3lime = $uniqworkbook->add_format(align => 'center', bg_color => 'lime');
   my $format4 = $uniqworkbook->add_format(align => 'center', bottom => 1);
   my $format5 = $uniqworkbook->add_format(color => 'white', bg_color => 'red', bold => '1');
   my $format6 = $uniqworkbook->add_format(align => 'center', color => 'red', bold => '1');
   my $format7 = $uniqworkbook->add_format(bold => '1', align => 'center', color => 'red', size => 13);
   my $format8 = $uniqworkbook->add_format(bold => '1', align => 'center', top => '2', right => '2', bottom => '2');
   my $format9 = $uniqworkbook->add_format(bg_color => $lightgrey, top => '1', bottom => '1', left => '1', right => '1');
   my $format10 = $uniqworkbook->add_format(bg_color => $lightgrey, top => '1', bottom => '1', left => '1', right => '1', align => 'center');
   my $urlformat = $uniqworkbook->add_format( color => 'blue', underline => 1, align => 'center');
   my $urlformat2 = $uniqworkbook->add_format( color => 'blue', underline => 1, align => 'center', bg_color => 'lime', bold => '1');
   my $targetformat = $uniqworkbook->add_format(italic => 1, size => 8);
   my $historytitleformat = $uniqworkbook->add_format(align => 'center', bold => 1, top => 1, right => 1);
   my $emptytopformat = $uniqworkbook->add_format(top => 1);
   my $emptybottomformat = $uniqworkbook->add_format(bottom => 1);
   my $emptybottomrightformat = $uniqworkbook->add_format(right => 1, align => 'center', bottom => 1);
   my $leftleftformat = $uniqworkbook->add_format(left => 1);
   my $historydateformat = $uniqworkbook->add_format(align => 'right');
   my $historydatebottomformat =  $uniqworkbook->add_format(align => 'right', bottom => 1);
   my $historyemergencyformat = $uniqworkbook->add_format(align => 'center', bg_color => 'red', top => 1, right => 1, left => 1, bottom => 1);
   my $historycriticalformat = $uniqworkbook->add_format(align => 'center', bg_color => 52, top => 1, right => 1, left => 1, bottom => 1);
   my $historymajorformat = $uniqworkbook->add_format(align => 'center', bg_color => 'yellow', top => 1, right => 1, left => 1, bottom => 1);
   my $historyminorformat = $uniqworkbook->add_format(align => 'center', bg_color => 'lime', top => 1, right => 1, left => 1, bottom => 1);
   my $historytotalformat = $uniqworkbook->add_format(align => 'center', bold => 1, top => 1, right => 1, left => 1, bottom => 1);
   my $totallabelformat = $uniqworkbook->add_format(bold => 1, size => 13, left => 1);
   my $unsubmittedlabelformat = $uniqworkbook->add_format(bold => 1, size => 13, bottom => 1, left => 1);
   my $olaformat = $uniqworkbook->add_format(bold => 1, color => 'red', align => 'center', right => 1);
   my $centerrightformat = $uniqworkbook->add_format(align => 'center', right => 1);
   my $redbottomrightbold  = $uniqworkbook->add_format(bold => '1', align => 'center', color => 'red', size => 13, bottom => 1, right => 1);
   my $nonpciheadingformat = $uniqworkbook->add_format(bold => '1', align => 'left');
   my $nonpciwarningformat = $uniqworkbook->add_format(italic => '1', align => 'left', size=>10);
   my $falseformat = $uniqworkbook->add_format(align => 'left', bottom => 1, left => 1);
   my $falsenumformat = $uniqworkbook->add_format(align => 'center', bg_color => 'lime', bold => 1, bottom => 1, right => 1);



########################################################
### CREATE REGION TABLE IN EMAIL NOTIFICATION (1)

    my $row;
    my $impactrow;
    my $hostscanned = scalar keys %{$region_ticketurls{$region}[2]};
    my $pcihost = scalar keys %{$region_ticketurls{$region}[1]};
    my $uniqpci = scalar (keys %{$qid_perregion{$region}});
    $row = '<tr align="center"><td>' . $region . '</td>';    
    
    my $vulnperregion = 0;
    my $pcivulnperregion = 0;
    foreach my $ip (keys %{$region_ticketurls{$region}[1]}){
       $vulnperregion += scalar @{$ip_vulnentries{$ip}};
       foreach my $vulnentry(@{$ip_vulnentries{$ip}}){
          ++$pcivulnperregion if $$vulnentry[9] eq 'yes';
       }
    }


#########################################################
$impactrow = 

'<tr><th></th><th colspan="5">' . $region . '</th></tr>' . 

'<tr align="center"> ' .
'<td></td>' .
'<td bgcolor="red">Emergency</td><td bgcolor="orange">Critical</td><td bgcolor="yellow">Major</td><td bgcolor="lime">Minor</td><td>TOTAL</td>' . 
'</tr>' . 

'<tr align="center"> ' .
'<td>' . $region_ticketurls{$region}[3]{'launchdate'} . '</td>'. 
'<td>' . $region_ticketurls{$region}[9]{emergency} . '</td>' .
'<td>' . $region_ticketurls{$region}[9]{critical} . '</td>' .
'<td>' . $region_ticketurls{$region}[9]{major} . '</td>' .
'<td>' . $region_ticketurls{$region}[9]{minor} . '</td>' .
'<td>' . $region_ticketurls{$region}[9]{total} . '</td>' .
'</tr>'.

'<tr align="center"> ' .
(defined $lastregion{$region}[3]{'launchdate'}?"<td>$lastregion{$region}[3]{'launchdate'}</td>":'') .
(defined $lastregion{$region}[3]{'launchdate'}?"<td>$lastregion{$region}[4]{emergency}</td>":'') .
(defined $lastregion{$region}[3]{'launchdate'}?"<td>$lastregion{$region}[4]{critical}</td>":'') .
(defined $lastregion{$region}[3]{'launchdate'}?"<td>$lastregion{$region}[4]{major}</td>":'') .
(defined $lastregion{$region}[3]{'launchdate'}?"<td>$lastregion{$region}[4]{minor}</td>":'') .
(defined $lastregion{$region}[3]{'launchdate'}?"<td>$lastregion{$region}[4]{total}</td>":'') .
'</tr>'.

'<tr align="center"> ' .
(defined $thirdregion{$region}[3]{'launchdate'}?"<td>$thirdregion{$region}[3]{'launchdate'}</td>":'') .
(defined $thirdregion{$region}[3]{'launchdate'}?"<td>$thirdregion{$region}[4]{emergency}</td>":'') .
(defined $thirdregion{$region}[3]{'launchdate'}?"<td>$thirdregion{$region}[4]{critical}</td>":'') .
(defined $thirdregion{$region}[3]{'launchdate'}?"<td>$thirdregion{$region}[4]{major}</td>":'') .
(defined $thirdregion{$region}[3]{'launchdate'}?"<td>$thirdregion{$region}[4]{minor}</td>":'') .
(defined $thirdregion{$region}[3]{'launchdate'}?"<td>$thirdregion{$region}[4]{total}</td>":'') .
'</tr>'.

'<tr align="center"> ' .
(defined $fourthregion{$region}[3]{'launchdate'}?"<td>$fourthregion{$region}[3]{'launchdate'}</td>":'') .
(defined $fourthregion{$region}[3]{'launchdate'}?"<td>$fourthregion{$region}[4]{emergency}</td>":'') .
(defined $fourthregion{$region}[3]{'launchdate'}?"<td>$fourthregion{$region}[4]{critical}</td>":'') .
(defined $fourthregion{$region}[3]{'launchdate'}?"<td>$fourthregion{$region}[4]{major}</td>":'') .
(defined $fourthregion{$region}[3]{'launchdate'}?"<td>$fourthregion{$region}[4]{minor}</td>":'') .
(defined $fourthregion{$region}[3]{'launchdate'}?"<td>$fourthregion{$region}[4]{total}</td>":'') .
'</tr>';

push @regionimpacts, $impactrow;
###########################################################
    
    my $lastvulnperregion = 0;
    my $lastpcivulnperregion = 0;
    
    foreach my $ip (keys %{$lastregion{$region}[1]}){
       $lastvulnperregion += scalar @{$lastip_vulnentries{$ip}};
       foreach my $vulnentry(@{$lastip_vulnentries{$ip}}){
          ++$lastpcivulnperregion if $$vulnentry[2] eq 'yes';
       }
    }
    
    
   
    
##################################################################

# PRINT THE FIRST TABLE IN EXCEL (SUMMARY TABLE) AND ALSO ON THE SCREEN

  print "\n\n------------------------------------------------------\n";
  print "Region: $region\n";
  print "Total Hosts Scanned: ";
  print scalar keys %{$region_ticketurls{$region}[2]}, "\n";
  print ($process_nonpci eq 'no'?"Hosts w/ PCI Vulnerabilities: ":"Hosts w/ Vulnerabilities: ");
  if (defined $region_ticketurls{$region}){
  print scalar keys %{$region_ticketurls{$region}[1]}, "\n";
  }else{
     say "UNDEFINED 1st ELEMENT";
  }
  print "Unique " . ($process_nonpci eq 'no'?"PCI Vulnerabilities: ":"Vulnerabilities: ") . scalar (keys %{$qid_perregion{$region}}) . "\n";   
  print "Total PCI Vulnerabilities: $pcivulnperregion\n";
  print "Total Vulnerabilities: $vulnperregion\n\n";
  print "Creating spreadsheet report...\n\n";
  $uniqsheet->write(0, 0, 'Scan Summary', $headingformat);
  $uniqsheet->write(0, 1, 'Current Scan', $headingformat);


my ($existingtickets, $newlycreated, $totaloutstanding, $olaviolations, $unsubmittedtickets);
  $totaloutstanding = $olaviolations = $unsubmittedtickets = $newlycreated = $existingtickets = 0;
  
  $existingtickets = $region_ticketurls{$region}[10]{emergency} + $region_ticketurls{$region}[10]{critical} + $region_ticketurls{$region}[10]{major} + $region_ticketurls{$region}[10]{minor};
  $newlycreated = $region_ticketurls{$region}[10]{newemergency} + $region_ticketurls{$region}[10]{newcritical} + $region_ticketurls{$region}[10]{newmajor} + $region_ticketurls{$region}[10]{newminor};
  $totaloutstanding = $existingtickets + $newlycreated;
  $unsubmittedtickets = $vulnperregion - $totaloutstanding;

if ($process_mode == 1){
  $uniqsheet->write(0, 2, 'Previous Scan', $headingformat);
  $uniqsheet->write(1, 2 , $lastregion{$region}[3]{'launchdate'}, $format3);
  $uniqsheet->write(2, 2 , scalar keys %{$lastregion{$region}[2]}, $format3);
  $uniqsheet->write(3, 2 , ($process_nonpci eq 'no'?scalar keys %{$lastregion{$region}[1]}:scalar keys %{$lastregion{$region}[11]}), $format3);

  $uniqsheet->write(4, 2 , ($process_nonpci eq 'yes'?$lastvulnperregion:scalar keys %{$lastqid_perregion{$region}}), $format3); 
  $uniqsheet->write(5, 2 , $lastpcivulnperregion, $format4);
  $uniqsheet->merge_range(7, 0, 7, 1, 'Service Desk Tickets', $headingformat);  
  $uniqsheet->write(8, 0 , 'Existing', $leftleftformat);
  $uniqsheet->write(8, 1 , $existingtickets, $centerrightformat);
  $uniqsheet->write(9, 0 , 'Newly Created', $leftleftformat);
  $uniqsheet->write(9, 1 , $newlycreated, $centerrightformat);
  $uniqsheet->write(10, 0 , 'Total Outstanding', $leftleftformat);
  $uniqsheet->write(10, 1 , $totaloutstanding, $centerrightformat);
  $uniqsheet->write(11, 0 , 'OLA Violations', $leftleftformat);
  $uniqsheet->write(12, 0 , 'Unsubmitted Tickets', $unsubmittedlabelformat);
  $uniqsheet->merge_range(14,0,14,9, "(Scan Targets - " . $region_ticketurls{$region}[7] . ")", $targetformat);
  $uniqsheet->write(2, 3 , $region_ticketurls{$region}[3]{'launchdate'}, $historydateformat);
  $uniqsheet->write(3, 3 , $lastregion{$region}[3]{'launchdate'}, $historydateformat);
  $uniqsheet->write(4, 3 , $thirdregion{$region}[3]{'launchdate'}, $historydateformat);
  $uniqsheet->write(5, 3 , $fourthregion{$region}[3]{'launchdate'}, $historydatebottomformat);
}
 
  $uniqsheet->write(1, 0 , 'Date of Scan', $leftleftformat);
  $uniqsheet->write(1, 1 , $region_ticketurls{$region}[3]{'launchdate'}, $format3);
  $uniqsheet->write(2, 0 , 'Total Hosts Scanned', $leftleftformat);
  $uniqsheet->write(2, 1 , scalar keys %{$region_ticketurls{$region}[2]}, $format3);
  $uniqsheet->write(3, 0 , 'Hosts with PCI Vulnerabilities', $leftleftformat);
  $uniqsheet->write(3, 1 , ($process_nonpci eq 'no'?scalar keys %{$region_ticketurls{$region}[1]}:scalar keys %{$region_ticketurls{$region}[11]}), $format3);
  $uniqsheet->write(4, 0 , ($process_nonpci eq 'yes'?'Total Vulnerabilities':'Unique PCI Vulnerabilities'), $leftleftformat);
  $uniqsheet->write(4, 1 , ($process_nonpci eq 'yes'?$vulnperregion:scalar keys %{$qid_perregion{$region}}), $format3);
  $uniqsheet->write(5, 0 , 'PCI Vulnerabilities', $totallabelformat);
  $uniqsheet->write(5, 1 , $pcivulnperregion, $format7); 
  $uniqsheet->write(6, 0 , 'False Positives', $falseformat);
  $uniqsheet->merge_range(0,4,0,8, ($process_mode == 1?"Changes from the Previous Scans":"Breakdown per Impact"), $historytitleformat);
  $uniqsheet->write(1, 4 , "  Emergency  ", $historyemergencyformat);
  $uniqsheet->write(1, 5 , "Critical", $historycriticalformat);
  $uniqsheet->write(1, 6 , "Major", $historymajorformat);
  $uniqsheet->write(1, 7 , "Minor", $historyminorformat);
  $uniqsheet->write(1, 8 , "TOTAL", $historytotalformat);
  $uniqsheet->write(5, 3 , '', $emptybottomformat) if not defined $fourthregion{$region}[3]{'launchdate'};
  $uniqsheet->write(2, 4 , $region_ticketurls{$region}[9]{emergency}, $format3);
  $uniqsheet->write(2, 5 , $region_ticketurls{$region}[9]{critical}, $format3);
  $uniqsheet->write(2, 6 , $region_ticketurls{$region}[9]{major}, $format3);
  $uniqsheet->write(2, 7 , $region_ticketurls{$region}[9]{minor}, $format3);
  $uniqsheet->write(2, 8 , $region_ticketurls{$region}[9]{total}, $centerrightformat);
  
  
 unless (not defined $lastregion{$region}[3]{'launchdate'}){
  if ($process_mode == 1){
     $uniqsheet->write(3, 4 , $lastregion{$region}[4]{emergency}, $format3);
     $uniqsheet->write(3, 5 , $lastregion{$region}[4]{critical}, $format3);
     $uniqsheet->write(3, 6 , $lastregion{$region}[4]{major}, $format3);
     $uniqsheet->write(3, 7 , $lastregion{$region}[4]{minor}, $format3);
     $uniqsheet->write(3, 8 , $lastregion{$region}[4]{total}, $centerrightformat);
  }
 }else{
   $uniqsheet->write(3, 8 , '', $centerrightformat)
}
 
unless (not defined $thirdregion{$region}[3]{'launchdate'}){
  if ($process_mode == 1){
      $uniqsheet->write(4, 4 , $thirdregion{$region}[4]{emergency}, $format3);
      $uniqsheet->write(4, 5 , $thirdregion{$region}[4]{critical}, $format3);
      $uniqsheet->write(4, 6 , $thirdregion{$region}[4]{major}, $format3);
      $uniqsheet->write(4, 7 , $thirdregion{$region}[4]{minor}, $format3);
      $uniqsheet->write(4, 8 , $thirdregion{$region}[4]{total}, $centerrightformat);
  }
}else{
   $uniqsheet->write(4, 8 , '', $centerrightformat)
}
   


unless (not defined $fourthregion{$region}[3]{'launchdate'}){ 
  if ($process_mode == 1){
      $uniqsheet->write(5, 4 , $fourthregion{$region}[4]{emergency}, $format4);
      $uniqsheet->write(5, 5 , $fourthregion{$region}[4]{critical}, $format4);
      $uniqsheet->write(5, 6 , $fourthregion{$region}[4]{major}, $format4);
      $uniqsheet->write(5, 7 , $fourthregion{$region}[4]{minor}, $format4);
      $uniqsheet->write(5, 8 , $fourthregion{$region}[4]{total}, $emptybottomrightformat);
  }
}else{
  $uniqsheet->write(5, 4 , '', $emptybottomformat);
  $uniqsheet->write(5, 5 , '', $emptybottomformat);
  $uniqsheet->write(5, 6 , '', $emptybottomformat);
  $uniqsheet->write(5, 7 , '', $emptybottomformat);
  $uniqsheet->write(5, 8 , '', $emptybottomrightformat);

}  
  
  
  $uniqsheet->write(0, 3 , '', $emptytopformat);
  $uniqsheet->write(7, 1 , '', $historytitleformat) if $process_mode == 1;




#  PRINT SECOND TABLE (UNIQUE PCI VULNERABILITIES 

#   $uniqsheet->write(9, 0 , 'Unique PCI Vulnerabilities  ', $headingformat);
#   $uniqsheet->write(9, 1 , ' Hosts Affected ', $headingformat);
#   my $qidstartcell = 10;
#   my $qidcount = 1;
#   foreach my $qid (keys %{$qid_perregion{$region}}){
#       $uniqsheet->write($qidstartcell, 0, $qidcount . '.) ' . 'QID:' . $qid . ' - ' . "\"${$qid_perregion{$region}}{$qid}[0]\"" );
#       my $affectedhostcount = 0;
#       my %affectedhosts;
#       foreach my $ip (keys %{${$qid_perregion{$region}}{$qid}[1]}){
#           $ip =~ s/:\d+$//g;
#           $affectedhosts{$ip} = '';
#        }
#           $uniqsheet->write($qidstartcell, 1, scalar keys %affectedhosts, $format3);
#           ++$qidstartcell;
#           ++$qidcount;
#   }
      
     
#  PRINT THIRD TABLE (VULNERABILITIES AND AFFECTED HOSTS

#   my $headingstartcell = $qidstartcell + 2;
   my $headingstartcell;
   if ($process_mode == 1){
        # $uniqsheet->freeze_panes(15, 0);
         $headingstartcell = 15;
   }else{
         $headingstartcell = 8;
         $uniqsheet->freeze_panes(9, 0);
   }
   $uniqsheet->write($headingstartcell, 0, "Vulnerabilities and Affected Hosts", $headingformat);  
   $uniqsheet->write($headingstartcell, 1, "OS Detected", $headingformat);
   $uniqsheet->write($headingstartcell, 2, "Ticket No.", $headingformat);
   $uniqsheet->write($headingstartcell, 3, " Ticket Status ", $headingformat);
   $uniqsheet->write($headingstartcell, 4, "  Assignee Group  ", $headingformat);  
   $uniqsheet->write($headingstartcell, 9, " Create SD Ticket? ", $headingformat);
   $uniqsheet->write($headingstartcell, 10, " CVEs Covered ", $headingformat);
   $uniqsheet->write($headingstartcell, 11, " Non-Excepted CVEs ", $headingformat);
   $uniqsheet->write($headingstartcell, 5, "  Ticket Age  ", $headingformat);
   $uniqsheet->write($headingstartcell, 6, " CVSS Score ", $headingformat);
   $uniqsheet->write($headingstartcell, 7, "   Impact   ", $headingformat);
   $uniqsheet->write($headingstartcell, 8, "OLA / Delay", $headingformat);

   my $affectedstartcell = $headingstartcell + 1;      
   my $qidcount2 = 1;
   my $falsecount = 0;

# WRITE QID::TITLE
      foreach my $qid (sort { $qid_perregion{$region}{$b}[5] <=> $qid_perregion{$region}{$a}[5] ||  $qid_perregion{$region}{$b}[3] <=> $qid_perregion{$region}{$a}[3] }keys %{$qid_perregion{$region}}){ 
            if (filter_vuln($qid_perregion{$region}{$qid}[3], $qid_perregion{$region}{$qid}[4], $region_ticketurls{$region}[5]) eq 'yes'){
               next unless defined $lastqid{$qid};
            }                                             
            $uniqsheet->merge_range($affectedstartcell,0,$affectedstartcell,5, "$qidcount2\.) QID::$qid" . ' - ' . "\"${$qid_perregion{$region}}{$qid}[0]\" " . (${$qid_perregion{$region}}{$qid}[6] eq 'yes'?'(PCI Vuln)':'')  , $qidformat);
            $uniqsheet->write($affectedstartcell, 6, $qid_perregion{$region}{$qid}[3], $format9);
            $uniqsheet->write($affectedstartcell, 7, get_impact($qid_perregion{$region}{$qid}[3], 'impact', $qid_perregion{$region}{$qid}[4]), $format10);
            my $ola = get_impact($qid_perregion{$region}{$qid}[3], 'ola', $qid_perregion{$region}{$qid}[4]);
            $uniqsheet->write($affectedstartcell, 8, ($ola . ($ola > 1?' days':' day')), $format9);
            $uniqsheet->write($affectedstartcell, 10, $qid_perregion{$region}{$qid}[7]);

            ++$qidcount2;
            ++$affectedstartcell;
             
# WRITE AFFECTED HOSTS/IP, TICKET STATUS, ASSIGNEE GROUP, VULN IGNORE STATUS

         foreach my $ip_port (keys %{$qid_perregion{$region}{$qid}[1]}){
#1.) TEST IF IT IS A FILTERED VULN (E.G., IF EMERGENCY AND MAJOR WERE NOT SELECTED.
              if (filter_vuln($qid_perregion{$region}{$qid}[3], $qid_perregion{$region}{$qid}[4], $region_ticketurls{$region}[5]) eq 'yes'){  

#2.) THEN TEST IF IT IS IN THE LASTQID. IF IT IS, WRITE IT, IF NOT, SKIP, DON'T WRITE IT IN THE SPREADSHEET                    
                 unless (defined $lastqid{$qid} && defined $lastqid{$qid}{$ip_port}){
                     next;
                 }                     
              }
           
              (my $ip) = $ip_port =~ /^(\d+\.\d+\.\d+\.\d+).*/;
              say "$qid $ip_port IS NOT DEFINED" if !defined ${$qid_perregion{$region}}{$qid}[1]{$ip_port}[3];
              
              $uniqsheet->write($affectedstartcell, 0, " $ip_port");           
              $uniqsheet->write($affectedstartcell, 1, (defined ${$qid_perregion{$region}}{$qid}[1]{$ip_port}[3]?"(${$qid_perregion{$region}}{$qid}[1]{$ip_port}[3])":''));
            
############# WRITE THE NON-EXCEMPT CVEs AND NUMBER OF FALSE POSITIVES              
                                              
                 my $excempted_cve;
                    if (defined $qid_perregion{$region}{$qid}[7]){
         
                      for (split(',', $qid_perregion{$region}{$qid}[7])){
                           if (!exists $cve_data{$ip}{$_}){
                              $excempted_cve = 0;
                              $cve_data{$ip}{nonexcept}{$_} = undef;
                           }else{
                              $excempted_cve = 1 unless (defined $excempted_cve && $excempted_cve == 0);
                           }
                      }                      
                    }  
                    
                    
### NON-EXCEMPT CVEs                 
                    
                 my @allcve;
                 @allcve = split(',', $qid_perregion{$region}{$qid}[7]) if defined $qid_perregion{$region}{$qid}[7];
                 my %allcve;
                 my @allcvenonexcept;
                 
                 for (@allcve){
                    $allcve{$_} = undef;
                 }
                 
                 foreach my $cve (keys %{$cve_data{$ip}{nonexcept}}){
                    push @allcvenonexcept, $cve if exists $allcve{$cve};
                 }
                 $uniqsheet->write($affectedstartcell, 11, ((scalar @allcvenonexcept > 0 && scalar @allcvenonexcept != scalar @allcve)?"(@allcvenonexcept)":''));
###########################   
                    
             if (${$qid_perregion{$region}}{$qid}[1]{$ip_port}[1] ne ''){
                    if (defined $excempted_cve && $excempted_cve == 1){
                       ++$falsecount;
                        $uniqsheet->write_url($affectedstartcell, 2, 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?OP=SEARCH+FACTORY=cr+SKIPLIST=1+QBE.EQ.id=' . ${$qid_perregion{$region}}{$qid}[1]{$ip_port}[1], ${$qid_perregion{$region}}{$qid}[1]{$ip_port}[0], $urlformat2);                       
                    }else{
                        $uniqsheet->write_url($affectedstartcell, 2, 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?OP=SEARCH+FACTORY=cr+SKIPLIST=1+QBE.EQ.id=' . ${$qid_perregion{$region}}{$qid}[1]{$ip_port}[1], ${$qid_perregion{$region}}{$qid}[1]{$ip_port}[0], $urlformat);                       
                    }                    
              }else{                   
                    if (defined $excempted_cve && $excempted_cve == 1){
                       ++$falsecount;
                        $uniqsheet->merge_range($affectedstartcell,2,$affectedstartcell,5, "${$qid_perregion{$region}}{$qid}[1]{$ip_port}[0]", $format3lime);
                    }else{
                        $uniqsheet->merge_range($affectedstartcell,2,$affectedstartcell,5, "${$qid_perregion{$region}}{$qid}[1]{$ip_port}[0]", $format3);
                    }                  
              }
#############################################


              my $ticketinfo;
              if (defined $qid_perregion{$region}{$qid}[1]{$ip_port}[2]){
                  $ticketinfo = get_ticketinfo(\$inforesponse{$qid_perregion{$region}{$qid}[1]{$ip_port}[2]}, ['status', 'group', 'creationdate']);
              }else{           
                 $ticketinfo = {status => '', group => '', age => 0};
              }

              $uniqsheet->write($affectedstartcell, 3, $$ticketinfo{status}, $format3);
              $uniqsheet->write($affectedstartcell, 4, $$ticketinfo{group}, $format3);
              $uniqsheet->write($affectedstartcell, 5, ($$ticketinfo{age} == 0 && $update_status eq 'no'?'':$$ticketinfo{age}), $format3) unless ${$qid_perregion{$region}}{$qid}[1]{$ip_port}[0] =~ /no ticket yet/ ;
              my $oladelay = $$ticketinfo{age} - get_impact($qid_perregion{$region}{$qid}[3], 'ola');
              ++$olaviolations if defined $oladelay && $oladelay > 0;
              $uniqsheet->write(11, 1 , (defined $olaviolations?$olaviolations:'0'), $olaformat) if $process_mode == 1;
              $uniqsheet->write($affectedstartcell, 8, ($oladelay < 1?'':$oladelay), $format3);

           
              ++$affectedstartcell;
                    
        }
        ++$affectedstartcell;

      }
      
     ++$affectedstartcell;
     
      $uniqsheet->write(6, 1 , $falsecount, $falsenumformat); 
      $uniqsheet->write(12, 1 , $unsubmittedtickets, $redbottomrightbold) if $process_mode == 1;

 
### WHEN PROCESS_NONPCI == NO, LIST DOWN THE EXISTING NON-PCI TICKETS AT THE BOTTOM OF THE SPREADSHEET. 
     
 if ($process_nonpci eq 'no'){
    unless ((scalar (keys %{$nonpci_tickets{$region}})) < 1){
        $uniqsheet->write($affectedstartcell, 0, "Existing Non-PCI Vuln. Tickets", $nonpciheadingformat);
        $uniqsheet->merge_range($affectedstartcell,1,$affectedstartcell, 8, " (Vulnerability status unverified. Must process the scan results with process_nonpci = yes)" , $nonpciwarningformat);
        ++$affectedstartcell;
        foreach my $qid (keys %{$nonpci_tickets{$region}}){
           $uniqsheet->merge_range($affectedstartcell,0,$affectedstartcell,5, "$qidcount2\.) QID::$qid" . ' - ' . "\"$nonpci_tickets{$region}{$qid}{title}\"" , $qidformat);
           ++$affectedstartcell;
           foreach my $ip_port (keys %{$nonpci_tickets{$region}{$qid}}){
              next if $ip_port eq 'title';
               $uniqsheet->write($affectedstartcell, 0, " $ip_port");
               $uniqsheet->write_url($affectedstartcell, 2, $nonpci_tickets{$region}{$qid}{$ip_port}[1], $nonpci_tickets{$region}{$qid}{$ip_port}[0], $urlformat);
               ++$affectedstartcell; 
           }
        }
     }
  }

########################################################
### CREATE REGION TABLE IN EMAIL NOTIFICATION

#my $row;
#my $hostscanned = scalar keys %{$region_ticketurls{$region}[2]};
#my $pcihost = scalar keys %{$region_ticketurls{$region}[1]};
#my $uniqpci = scalar (keys %{$qid_perregion{$region}});
#$row = '<tr align="center"><td>' . $region . '</td>';    
#my $vulnperregion = 0;
#foreach my $ip (keys %{$region_ticketurls{$region}[1]}){
#      $vulnperregion += scalar @{$ip_vulnentries{$ip}};
#}

$row .= '<td>' . $hostscanned . '</td>' . '<td>' . ($process_nonpci eq 'yes'?$vulnperregion:scalar (keys %{$qid_perregion{$region}})) . '</td>' . '<td>' . $pcivulnperregion . '</td>' . '<td>' . $totaloutstanding . '</td>' . '<td>' . $olaviolations . '</td>' . '<td bgcolor="lime">' . $falsecount . '</td>' . '<td>' . $unsubmittedtickets . '</td>' . '</tr>';
push @regions, $row;


### FINALLY, LOG THE STATS IN OUR $log_file TO BE CONSUMED BY SPLUNK FOR CHARTS AND GRAPHS GENERATION

if (lc($write_log) eq 'yes'){
   open LOGFILE, ">>", $log_file or die "Unable to open $log_file for writing. Check permission or connectivity $!\n";   
   print LOGFILE "$region_ticketurls{$region}[3]{'launchdate'},$region,$hostscanned," . ($process_nonpci eq 'yes'?$vulnperregion:scalar (keys %{$qid_perregion{$region}})) . ",$pcivulnperregion,$totaloutstanding,$olaviolations,$falsecount,$unsubmittedtickets,$region_ticketurls{$region}[9]{emergency},$region_ticketurls{$region}[9]{critical},$region_ticketurls{$region}[9]{major},$region_ticketurls{$region}[9]{minor}\n";
   close LOGFILE;      
}
    
#########################################################

    autofit_columns($uniqsheet);

}



###########################################################################




#print "\n\n\n\nEND TIME: " . scalar localtime , "\n";
#print LOGFILE "\n\n\n\nEND TIME: " . scalar localtime , "\n";
print "\n\n======================================================\n\n\n";
#print LOGFILE "\n\n======================================================\n\n\n";
#print "Sending report to $notify_emails...\n\n";
#close (LOGFILE);



## 11.) COMPOSE THE EMAIL NOTIFICATION


# CREATE THE TOPTEN VULNERABLE HOST

my @toptentable = create_topten(\%topvulnhosts_ticketurls);

# CREATE THE TABLE OF TICKETS PER REGION

#my $regiontable = create_region();

# ELAPSED TIME IN MINUTES

my $elapsedtime = (time() - $^T) / 60;
$elapsedtime = sprintf("%.2f", $elapsedtime);
my $totalticketscreated = $ipcount + $pcivulncount + (scalar @regions > 1?scalar @regions:0);
my ($vulndiscovered, $totalvulnunique);
if ($process_nonpci eq 'yes'){
   $vulndiscovered = 'Vulnerabilities';
}else{
   $vulndiscovered = 'PCI Vulnerabilities';
}

if ($process_nonpci eq 'yes'){
   $totalvulnunique = 'Total Vulnerabilities';
}else{
   $totalvulnunique = 'Unique PCI Vulns.';
}



my $message = <<"MESSAGE";

<p style="font-family:Calibri;font-size:11pt;">FYI:</p>
<p style="font-family:Calibri;font-size:11pt;">
Information Security Monitoring & Response team has done a vulnerability assessment on all the hosts in the following regions. The table below provides a summary of the result:
</p>


<table style="font-family:Calibri;font-size:10pt;" border=1 cellspacing=0 cellpadding=2>
<thead>
<tr bgcolor="0000FF"; style="color:white;font-weight:bolder;font-size:11pt""><th>Region</th><th>Hosts Scanned</th><th>$totalvulnunique</th><th>PCI Vulnerabilities</th><th>Outstanding Tickets</th><th>OLA Violations</th><th>False Positives</th><th>Unsubmitted Tickets</th></font></tr>
</thead>
<tbody>
<i>

@regions

</i>
</tbody>
</table>

<p style="font-family:Calibri;font-size:11pt;">
$vulndiscovered discovered for the last four (4) weeks were broken down according to impact in the following table :
<table style="font-family:Calibri;font-size:10pt;" border=1 cellspacing=0 cellpadding=2>
<tbody>

@regionimpacts


</tbody>
</table>

<p style="font-family:Calibri;font-size:11pt;">
Hosts with the most number of issues discovered are listed below:
<table style="font-family:Calibri;font-size:10pt;margin-top: 0px;border=0 cellspacing=0 cellpadding=0">
<tr><td><i style="font-family:Calibri;font-size:10pt;">Top Vulnerable Hosts:</i><td></td></td></tr>
</table>
<table style="font-family:Calibri;font-size:10pt;" border=1 cellspacing=0 cellpadding=2>
<thead>
<tr bgcolor="33EBFF"><th>Host/IP Address</th><th>No. of Issues</th></tr>
</thead>
<tbody>
<i>

@toptentable

</i>
</tbody>
</table>
</p>

<br>
<p style="font-family:Calibri;font-size:11pt;margin-top: 0px;">
The attached spreadsheet(s) contain the list of all vulnerabilities discovered and their corresponding Service Desk tickets.
<p style="font-family:Calibri;font-size:11pt;margin-top: 0px;">
<p style="font-family:Calibri;font-size:11pt;margin-top: 0px;">


MESSAGE
  
### PLACE TWO LINES BELOW BEFORE MESSAGE EOF
#$regiontable
#<p><i style="font-family:Calibri;font-size:8pt";> (a total of $totalticketscreated SD tickets were submitted in $elapsedtime minutes)</i></p>



#print "MESSAGE LENGTH IS " . length($message), "\n";



my $emailthread = threads->create('send_notification', $message);
$emailthread->join();
print "\nDone.\n\n\n";



## CLEANUP ALL THE REMAINING THREADS.

while( (scalar threads->list) > 0   ){
     foreach my $thread (threads->list) {
        if( $thread->is_joinable ){ $thread->join;}
       }
}









##################################### SUBROUTINES #########################################



### SUB FOR EXTRACTING XML SCAN RESULTS DOWNLOADED FROM QUALYS
sub extract_fields{

  
   my $xml = shift;
 
   my $mode = shift; 
   my $report = shift;  
   my ($rootxpath, $catxpath, $vulnxpath);
   my @fields;
   
   if ($mode eq 'infos'){
       $catxpath = 'INFOS/CAT';
       $vulnxpath = 'INFO';
   }elsif($mode eq 'vulns'){
       $catxpath = 'VULNS/CAT';
       $vulnxpath = 'VULN';  
   }elsif($mode eq 'practices'){
       $catxpath = 'PRACTICES/CAT';
       $vulnxpath = 'PRACTICE';
   }else{
       $catxpath = 'SERVICES/CAT';
       $vulnxpath = 'SERVICE';
   }
       my @scannodes = $xml->findnodes('/SCAN');
       foreach my $scan (@scannodes){
           my $scandate;
           my @header =  $scan->findnodes('HEADER/KEY');  
          foreach (@header){     
              if ($_->{value} eq 'DATE'){
                  $scandate = $_->to_literal;
                  last;
              }
         }
         my @ipnodes = $scan->findnodes('IP'); 
         foreach my $ip (@ipnodes){
             my @vulnscat = $ip->findnodes($catxpath);
             foreach my $vulncat (@vulnscat){
                 my @vulns = $vulncat->findnodes($vulnxpath);
                 foreach my $vuln(@vulns){

# SKIP VULN ENTRIES OF IPs WHICH ARE NOT INCLUDED IN THE TARGET ASSET_GROUP. WHEN THE IPs OF SELECTED ASSET GROUP(S) ARE ALSO INCLUDED
# IN ANOTHER ASSET GROUP. E.G., 'My.Co EXTERNAL' IS A SUBSET OF 'My US PCI', THE LIST OF SCANS THAT WILL BE RETRIEVED INCLUDES My.Co US PCI AS THE TARGET 
# INSTEAD OF My.Co EXTERNAL.


                      unless (defined $ip_regionmap{$ip->{value}}){
                         next;
                      }
                      
                      $region_ticketurls{$ip_regionmap{$ip->{value}}}[2]{$ip->{value}} = '' if $report eq 'current';    # SAVE IP AS HASH KEYS (THIS WILL PROVIDE COUNT FOR HOSTS WITH VULNERABILITIES
                      $region_ticketurls{$ip_regionmap{$ip->{value}}}[11]{$ip->{value}} = undef if $report eq 'current' && $vuln->findvalue('PCI_FLAG') == 1;    # SAVE IP AS HASH KEYS (THIS WILL PROVIDE COUNT FOR HOSTS WITH PCI VULNERABILITIES
                      $lastregion{$ip_regionmap{$ip->{value}}}[2]{$ip->{value}} = '' if $report eq 'last';  
                      $lastregion{$ip_regionmap{$ip->{value}}}[11]{$ip->{value}} = '' if $report eq 'last' && $vuln->findvalue('PCI_FLAG') == 1;  
                      my $ip_port = $ip->{value} . ":" . (defined $vulncat->{port}?$vulncat->{port}:'');
                     
if ($process_nonpci eq 'yes'){
                      push @fields, 
                           [  $ip->{value}, 
                              $ip_regionmap{$ip->{value}}, 
                              $vuln->findvalue('TITLE'), 
                              $vuln->findvalue('DIAGNOSIS'), 
                              $vuln->findvalue('RESULT'), 
                              $vuln->findvalue('CONSEQUENCE'), 
                              $vuln->findvalue('SOLUTION'), 
                              $ip->findvalue('OS'), 
                             (defined $vuln->findvalue('CVSS_BASE' ne '')?$vuln->findvalue('CVSS_BASE'):0), 
                             ($vuln->findvalue('PCI_FLAG') == 1?'yes':'no'), 
                             $vuln->findvalue('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/ID'), 
                             (defined $vuln->{cveid}?$vuln->{cveid}:''), 
                             $vuln->findvalue('BUGTRAQ_LIST/BUGTRAQ_ID/ID'), 
                             $ip->{name}, 
                             $vuln->{number}, 
                             (defined $vulncat->{port}?$vulncat->{port}:''),
                             DateTime::Format::ISO8601->parse_datetime($scandate)->strftime('%m/%d/%Y'),
                             ($vuln->findvalue('CVSS_TEMPORAL') ne ''?$vuln->findvalue('CVSS_TEMPORAL'):0),
                             ($vuln->findvalue('CORRELATION') ne ''?$vuln->findvalue('CORRELATION'):"")] if ($vuln->findvalue('CVSS_BASE') ne ''?$vuln->findvalue('CVSS_BASE'):0) >= 1 ;

            }else{
         
               push @fields, 
                           [  $ip->{value}, 
                              $ip_regionmap{$ip->{value}}, 
                              $vuln->findvalue('TITLE'), 
                              $vuln->findvalue('DIAGNOSIS'), 
                              $vuln->findvalue('RESULT'), 
                              $vuln->findvalue('CONSEQUENCE'), 
                              $vuln->findvalue('SOLUTION'), 
                              $ip->findvalue('OS'), 
                             (defined $vuln->findvalue('CVSS_BASE' ne '')?$vuln->findvalue('CVSS_BASE'):0), 
                             ($vuln->findvalue('PCI_FLAG') == 1?'yes':'no'), 
                             $vuln->findvalue('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE/ID'), 
                             (defined $vuln->{cveid}?$vuln->{cveid}:''), 
                             $vuln->findvalue('BUGTRAQ_LIST/BUGTRAQ_ID/ID'), 
                             $ip->{name}, 
                             $vuln->{number}, 
                             (defined $vulncat->{port}?$vulncat->{port}:''),
                             DateTime::Format::ISO8601->parse_datetime($scandate)->strftime('%m/%d/%Y'),
                             ($vuln->findvalue('CVSS_TEMPORAL') ne ''?$vuln->findvalue('CVSS_TEMPORAL'):0),
                             ($vuln->findvalue('CORRELATION') ne ''?$vuln->findvalue('CORRELATION'):"")] if ((($vuln->findvalue('CVSS_BASE') ne ''?$vuln->findvalue('CVSS_BASE'):0) >= 1 && ($vuln->findvalue('PCI_FLAG') == 1?'yes':'no') eq 'yes') || (defined $lastqid{$vuln->{number}} && defined $lastqid{$vuln->{number}}{$ip_port}));


            }

            }
        }

     }  
  }
  return \@fields;
}
#################################################################################


### SUB FOR DETERMINING WHETHER A VULNERABILITY IS FILTERED OR NOT (BASED ON IMPACT SELECTION (1-4)
sub filter_vuln{
 

my $cvss_score = shift @_;
my $correlation = shift @_;
my $selectedvulns = shift @_;

   unless (exists ($$selectedvulns{get_impact($cvss_score, 'impact', $correlation)})){
      return 'yes';
   }else{
      return 'no';
   }
}

#SUB FOR SAVING THE VULNERABILITIES EXTRACTED FROM THE LATEST SCAN RESULTS
sub save_vulns{
   
  my $vulnscount = 0; 
  foreach (@_){
     foreach (@{$_}){
        push (@{$ip_vulnentries{$$_[0]}}, $_); 
            $region_ticketurls{$ip_regionmap{$$_[0]}}[1]{$$_[0]} = '';     
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[0] = $$_[2];  
            my $qidkey = $$_[0] . ($$_[15] =~ /\d+/?":$$_[15]":''); 
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[2] = $$_[17]; 
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[3] = $$_[8];  
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[4] = $$_[18];  
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[5] = get_order(get_impact($$_[8], 'impact', $$_[18])); 
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[6] = $$_[9];
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[1]{$qidkey}[3] = $$_[7];
            $qid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[7] = $$_[11] if (defined $$_[11] && $$_[11] ne '');

     }
   
  }  


}

#SUB FOR SAVING THE VULNERABILITY STATS GATHERED FROM THE PREVIOUS THREE SCAN RESULTS
sub save_lastvulns{
   
foreach (@_){
    foreach (@{$_}){
          push (@{$lastip_vulnentries{$$_[0]}}, [$$_[8], $$_[18], $$_[9]]);      
          $lastregion{$ip_regionmap{$$_[0]}}[1]{$$_[0]} = '';                
          $lastqid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[0] = $$_[2];  
          my $lastqidkey = $$_[0] . ($$_[15] =~ /\d+/?":$$_[15]":'');
          $lastqid_perregion{$ip_regionmap{$$_[0]}}{ $$_[14]}[1]{$lastqidkey} = '';
   }
   
} 


}

sub save_thirdvulns{
   
foreach (@_){
    foreach (@{$_}){
      push (@{$thirdip_vulnentries{$$_[0]}}, [$$_[8], $$_[18]]);      
          $thirdregion{$ip_regionmap{$$_[0]}}[1]{$$_[0]} = '';                
          $thirdqid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[0] = $$_[2];  
          my $thirdqidkey = $$_[0] . ($$_[15] =~ /\d+/?":$$_[15]":'');
          $thirdqid_perregion{$ip_regionmap{$$_[0]}}{ $$_[14]}[1]{$thirdqidkey} = '';
   }
   
}  

}

sub save_fourthvulns{
   
foreach (@_){
    foreach (@{$_}){
      push (@{$fourthip_vulnentries{$$_[0]}}, [$$_[8], $$_[18]]);      
          $fourthregion{$ip_regionmap{$$_[0]}}[1]{$$_[0]} = '';                
          $fourthqid_perregion{$ip_regionmap{$$_[0]}}{$$_[14]}[0] = $$_[2];  
          my $fourthqidkey = $$_[0] . ($$_[15] =~ /\d+/?":$$_[15]":'');
          $fourthqid_perregion{$ip_regionmap{$$_[0]}}{ $$_[14]}[1]{$fourthqidkey} = '';
   }
   
}  

}

#################################################################################

sub get_order{ 
   my $impact = shift @_;
   my $order = 0;
   $order = 4 if $impact eq 'Emergency';
   $order = 3 if $impact eq 'Critical';
   $order = 2 if $impact eq 'Major';
   $order = 1 if $impact eq 'Minor';
   return $order;
}





#################################################################################

## 1.) ROUTINE TO SEND EMAIL NOTIFICATION

sub send_notification{
   my $ccto; 
   my $mailto;
   my $message = shift @_;
   require Win32::OLE;
   my $Outlook = new Win32::OLE('Outlook.Application');
   my $item = $Outlook->CreateItem(0);         
   $item->{'Subject'} = "Weekly Vulnerability Scan Notification - Outstanding " . ($process_nonpci eq 'no'?'PCI ':'') . "Vulnerabilities and SD Tickets - " . Time::Piece->strptime(scalar localtime, '%c')->strftime('%m/%d/%Y');

if ($notify_emails =~ /\,/){
   my @recepients = split(',', $notify_emails);
   $mailto = shift @recepients;
   $item->{'To'} = $mailto;
   $ccto = join (';', @recepients); 
   $item->{'Cc'} = $ccto;
}else{
   $item->{'To'} = $notify_emails;
}


print "Sending report to " . (!defined $mailto?"$notify_emails\n\n":"$mailto (CC:$ccto)...\n\n");


   $item->{'HTMLBody'} = $message;
   $item->{'From'} = $mailfrom;
   my $attach = $item->{'Attachments'};
   foreach (@attachments){
        (my $filename) = $_ =~ /\/(\d+ - .*)$/;  
        (my $region) = $filename =~ /\d+\s-\s(.*)_tickets\.xlsx/;        
        say "Copying $filename to $ticketspath..." ;
        copy("$_","$ticketspath") or say "Copying $_ to $ticketspath failed: $!\nTransfer this file manually to update our copy.";
        
        $attach->add($_);
        unlink $_;
   }
   $item->Send();
   return;
}


#################################################################################

## ROUTINE TO READ THE LATEST SPREADSHEETS CONTAINING SUBMITTED TICKETS OR EXISTING TICKETS

sub read_excel{
 
   require Win32::OLE;  
   my $submittedtickets = shift @_;
   my $sheet_reference = shift @_;
   my ($fullfile, $file, $filedir);  
   my $qid; 
   my $pcistatus;
   my %createonly_tickets;
   my %nonpci_tickets;
   my $title;
   


foreach (keys %{$submittedtickets}){
     
   if ($sheet_reference eq 'master'){
      $fullfile = $$submittedtickets{$_}{fullfile};
      $file = $$submittedtickets{$_}{file};
      $filedir = $$submittedtickets{$_}{filedir};
   }else{
      $fullfile = $$submittedtickets{$_}{adhocfullfile};
      $file = $$submittedtickets{$_}{adhocfile};
      $filedir = $$submittedtickets{$_}{adhocfiledir};
   }  
     
         
       say "Reading $file...";
       my $ticketexcel = Spreadsheet::XLSX -> new ($fullfile);  
       my $tempfile = $filedir . "_tmp_" . $file; 
      copy($fullfile, $tempfile) or die "Copy to temporary ($tempfile) file failed: $!";

      my $Excel = Win32::OLE->GetActiveObject('Excel.Application')
           || Win32::OLE->new('Excel.Application', 'Quit');
      $Excel->{DisplayAlerts}=0; 
      say "ABOUT TO OPEN EXCEL FILE" if $debug eq 'yes';
      my $Book = $Excel->Workbooks->Open($tempfile) or die "UNABLE TO OPEN $tempfile. IT WAS PROBABLY OPENED BY ANOTHER PROCESS OR EXCEL.EXE. CHECK CTRL+ALT+DELETE";   
      my $Sheet = $Book->Worksheets("Sheet1");
      $Sheet->Activate();
      foreach my $ticketsheet (@{$ticketexcel -> {Worksheet}}) {
          my $qidmarker = 0;
          $ticketsheet -> {MaxRow} ||= $ticketsheet -> {MinRow};
          foreach my $row (1 .. $ticketsheet -> {MaxRow}) {
              $ticketsheet -> {MaxCol} ||= $ticketsheet -> {MinCol};
              if (defined $ticketsheet -> {Cells} [$row] [0] -> {Val} &&  $ticketsheet -> {Cells} [$row] [0] -> {Val} =~ /QID\:\:/){
                 $qidmarker = 1;
                 ($qid) = $ticketsheet -> {Cells} [$row] [0] -> {Val} =~ /QID\:\:(\d+)/;
                 ($pcistatus) = $ticketsheet -> {Cells} [$row] [0] -> {Val} =~ /QID\:\:.*\"\s\((.*)\)/;
                 ($title) = $ticketsheet -> {Cells} [$row] [0] -> {Val} =~ /QID\:\:\d+\s-\s\"(.*)\"/;              
                  next;
              }         
              if (!defined $ticketsheet -> {Cells} [$row] [0] -> {Val}){
                   $qidmarker = 0;
              }
              if ($qidmarker == 1 ){
                   my $ip_port = $ticketsheet -> {Cells} [$row] [0] -> {Val};
                   if ($ip_port =~ /\(/){
                      $ip_port =~ s/\(.*\)//g;
                   }
                      $ip_port =~ s/\s+//g;                 
                   my $ticket;
                   $ticket = $ticketsheet -> {Cells} [$row] [2] -> {Val};   
                   my $format = 'new';
                   next if !defined $ticket;
                      if ($ticket !~ /^\d+$/ && $ticket !~ /no ticket yet/){
                          $ticket = $ticketsheet -> {Cells} [$row] [1] -> {Val};
                          $format = 'old';
                      }
                      
                   next if !defined $ticket;
                   my $create_this_ticket;
                   $create_this_ticket =  $ticketsheet->{Cells}[$row][9]->{Val} if (defined $ticketsheet->{Cells}[$row][9]->{Val});
                                                      
                   if ($ticket !~ /no ticket yet/ && $ticket =~ /^\d+$/){
                      say "SAVING TICKET DETAILS FOR $qid" if $debug eq 'yes';
                       my $cellObject;
                       if ($format eq 'new'){
                           $cellObject = $Sheet->Cells($row + 1,3);      
                       }else{
                           $cellObject = $Sheet->Cells($row + 1,2); 
                       }                                          
                       my $hyperlink;
                       $hyperlink = $cellObject->Hyperlinks(1)->Address;
### SAVE PCI VULN TICKETS                      
                       if (($process_nonpci eq 'no' && defined $pcistatus) || $process_nonpci eq 'yes'){
                          $lastqid{$qid}{$ip_port}{$ticket} = $hyperlink;
                       }
### SAVE NON-PCI VULN TICKETS
                       if ($process_nonpci eq 'no' && !defined $pcistatus){
                          say "SAVING $qid TO NONPCI_TICKETS" if $debug eq 'yes';
                          $nonpci_tickets{$_}{$qid}{title} = $title;
                          $nonpci_tickets{$_}{$qid}{$ip_port}[0] = $ticket;
                          $nonpci_tickets{$_}{$qid}{$ip_port}[1] = $hyperlink;
 
                       }
### SAVE "CREATE TICKET" FLAG                     
                   }else{
                         $createonly_tickets{$qid}{$ip_port} = $create_this_ticket;
                         next;                     
                   }
              }
           }
           $Book = $Excel->Workbooks->Close; 
  #         say "Removing temporary file $tempfile";
           unlink $tempfile; 
       }
    
  } 
  

   return (\%lastqid, \%createonly_tickets, \%nonpci_tickets);

}

#################################################################################


## 3.) ROUTINE TO EXPAND IP ADDRESS RANGES PER REGION



sub expload_iprange{

my $range = shift @_;   
my $region = shift @_;
my $remote_last_update = shift @_;
my $local_last_update;

my $ipcount = 0;
my $region_ip_blocks = $cfg->param("region_ip_blocks");

my $regionfile = $region_ip_blocks . "\/" . $region . "_IPs.txt";
my $ip;

### GET THE LAST UPDATE ON FILE AND COMPARE WITH LAST UPDATE ON THE QUALYS SERVER
if ((-e $regionfile && $process_mode == 1) && -s $regionfile){
   open LAST_UPDATE, "<" , $regionfile or die "Unable to read $regionfile for reading: $!";
   while (<LAST_UPDATE>){
      ($local_last_update) = $_ =~ /LAST\sUPDATE:\s+(.*)$/;
      close(LAST_UPDATE);
      last;   
   }
   
### RE-CREATE THE IP ADDRESS LISTING IF LOCAL LAST UPDATE IS EARLIER THAN REMOTE (QUALYS) LAST UPDATE
   if ((str2time($local_last_update)) < (str2time($remote_last_update))){
        unlink($regionfile) or warn "UNABLE TO DELETE $regionfile $!";
   }

}
   


if ((-e $regionfile && $process_mode == 1) && -s $regionfile){
    open my $range_fh, '<', $regionfile or die "Unable to open $regionfile for reading: $!";
    while(($ip = <$range_fh>)) {
        next if $ip =~ /^\s+$/;
        chomp $ip if defined $ip;
        $ip_regionmap{$ip} = $region ;
        $ipcount++;
    }

}elsif ((-e $regionfile && $process_mode == 2) && -s $regionfile){
    open RANGE_IP, '>>', $regionfile or die "Unable to open $regionfile for updating: $!"; 
    foreach (@{$range}){
      $ip = new Net::IP ($_) or die (Net::IP::Error());
      do {
          $ip_regionmap{$ip->ip()} = $region ;
          print RANGE_IP $ip->ip(), "\n";
          $ipcount++;
      } while (++$ip);
   } 
            
}else{
   
    open RANGE_IP, '>', $regionfile or die "Unable to open $regionfile for writing: $!"; 
    print RANGE_IP "LAST UPDATE: $remote_last_update\n";
    foreach (@{$range}){
      $ip = new Net::IP ($_) or die (Net::IP::Error());
      do {
          $ip_regionmap{$ip->ip()} = $region ;
          print RANGE_IP $ip->ip(), "\n";
          $ipcount++;
      } while (++$ip);
   }    
}



return $ipcount;


}


#################################################################################


## 4.) ROUTINE TO CREATE TABLE CONTAINING TICKETS PER REGION IN THE NOTIFICATION EMAIL

sub create_region{

my $ticketcounter = 0;
my $vulntable = '';

  foreach my $region (keys %region_ticketurls){
     if (!defined $region_ticketurls{$region}[1] || !defined $region_ticketurls{$region}[0]){
             next;
     }
   
     if (scalar @{$region_ticketurls{$region}} > 1){
         $vulntable .= '<table style="font-family:Calibri;font-size:10pt;" border=1 cellspacing=0 cellpadding=1><thead><tr style="font-family:Calibri;font-size:12pt;" bgcolor="FFFF00"><th colspan="6"><a href="http://servicedesk_url_changethis/CAisd/pdmweb.exe?OP=SEARCH+FACTORY=cr+SKIPLIST=1+QBE.EQ.id=' . $region_ticketurls{$region}[0][1] . '">' . $region . '<a></th></tr></thead>' ;
     }   
     foreach my $hostip (keys $region_ticketurls{$region}[1]){       
        $vulntable .= '<td colspan="6"; align="center"><b><a href="http://servicedesk_url_changethis/CAisd/pdmweb.exe?OP=SEARCH+FACTORY=cr+SKIPLIST=1+QBE.EQ.id=' . $vulnhosts_ticketurls{$hostip}[0][0] . '">' . $hostip . '</a><b></td><tr>';
        foreach (@{$vulnhosts_ticketurls{$hostip}[1]}){
           ++$ticketcounter;
           $vulntable .= ($ticketcounter == 7?'<tr>':'') . '<td><a href="http://servicedesk_url_changethis/CAisd/pdmweb.exe?OP=SEARCH+FACTORY=cr+SKIPLIST=1+QBE.EQ.id=' . $vulntickets_urls{$_} . '">' . $_ . '</a></td>';
           if ($ticketcounter == 7){ 
              $ticketcounter = 1;
           }
            
        }
        $ticketcounter = 0;           
        $vulntable .= '</tr>';
     }
     $vulntable .= '</table>'; 
  }
  return $vulntable; 
}

 
#################################################################################


## 5.) ROUTINE TO CREATE TABLE CONTAINING TOP TEN VULNERABLE HOSTS IN THE NOTIFICATION EMAIL

sub create_topten{
   
   my $toptencounter = 0; 
   my @vulnhosts;
   my $topvulnhosts = shift @_;
   
   foreach (reverse sort { (${$topvulnhosts}{$a}[0] <=> ${$topvulnhosts}{$b}[0]) } keys %{$topvulnhosts}){
       my $vulnurl = '<tr><td align="center">' . ${$topvulnhosts}{$_}[1] . $_ . (scalar keys %region_ticketurls > 1?" ($ip_vulnentries{$_}[0][1])":'') . '</td><td align="center">' . ${$topvulnhosts}{$_}[0] . '</td></tr>';
       push @vulnhosts, $vulnurl;
       ++$toptencounter;
       last if $toptencounter == 10;
   }
   return @vulnhosts;
}

#################################################################################
 
## 6.) ROUTINE TO GET TICKET INFORMATION (ASSIGNEE GROUP, TICKET STATUS)

sub queue_request{   
  my $ticketurlid = shift @_;
  my $sid = shift @_;
  my $async = shift @_;
  my $newurl = "http://servicedesk_url_changethis/CAisd/pdmweb.exe" . "?SID=" . $sid . '+FID=123+OP=SEARCH+FACTORY=cr+SKIPLIST=1+QBE.EQ.id=' . $$ticketurlid;
  my $reqid = $$async->add( HTTP::Request->new( GET => $newurl));
  say "RETURNING REQID $reqid IN QUEUE REQUEST" if $debug eq 'yes';
  return $reqid;
  
}




sub get_sid{
   
  my $ua = shift @_;
  my $username = shift @_;
  my $password = shift @_; 
  $$ua->credentials('servicedesk:80', '', $$username, $$password);
  $$ua->cookie_jar({});
  $$ua->proxy('http', 'http://127.0.0.1:9090/');
  $$ua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');
  my $sidreq = HTTP::Request->new(GET => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe');
  my $sidres = $$ua->request($sidreq);
  my ($sid) = $sidres->content =~ /SID=(\d+)\+/;   
  
  
  while (!defined $sid){
      say "\nSID request failed. Bad connection, domain account is locked out, or proxy not running? Retrying...\n";
      sleep 1;
      $sidres = $$ua->request($sidreq);
      ($sid) = $sidres->content =~ /SID=(\d+)\+/;   
  }       
     return $sid;

   
   
   
   
   
}

####################################################

sub get_ticketinfo{
   
   my $responseref = shift @_;
   my $inforef = shift @_;
 
   
   my %info;

     
   foreach (@{$inforef}){
        chomp;       
# TICKET STATUS
         if ($_ eq 'status'){
             my ($ticketstatus) = $$responseref->content =~ /default_trans_sym=\"(.*?)\";/;         
             if (not defined $ticketstatus or $ticketstatus eq ''){
                 $info{status} = '(unable to retrieve status)'; 
             }else{
                $info{status} = $ticketstatus;
             }
         }     
# ASSIGNEE GROUP
           if ($_ eq 'group'){
              my ($assigneegroup) = $$responseref->content =~ /\<INPUT TYPE\=hidden NAME\=group\_combo\_name VALUE\=\"(.*?)\"\>/;
              if (not defined $assigneegroup or $assigneegroup eq ''){
                  $info{group} = '(unable to retrieve assignee)'  
               }else{          
                  $info{group} = $assigneegroup;  
               }         
           } 
           
# CREATION DATE (AGE)
           
            if ($_ eq 'creationdate'){
               my ($creationdate) = $$responseref->content =~ /Open Date.*?(\d+)\"\)\;/; 
               my @createdate = (strftime("%Y", localtime($creationdate)), strftime("%m", localtime($creationdate)), strftime("%d", localtime($creationdate)));
               my @now = (strftime("%Y", localtime(time)), strftime("%m", localtime(time)), strftime("%d", localtime(time)));
               $info{age} = Delta_Days(@createdate, @now);                    
            }  
    }

    return \%info;


}





#################################################################################


## 7.) ROUTINE TO CREATE THE TICKET PER PCI VULNERABILITY


sub create_ticket{


   my $type = shift @_;
   my $parentticket = shift @_;
   my $content = shift @_; 
   my $custom_assignee_group = shift @_;
   my $description;   
   my $ua = new LWP::UserAgent(keep_alive => 1);
   $ua->credentials('servicedesk:80', '', $username, $password);
   my $indexurl = "http://servicedesk_url_changethis/CAisd/pdmweb.exe";
   $ua->cookie_jar({});
   my $sidreq = HTTP::Request->new(GET => $indexurl);
   my $assignee_group_hash; 
   
   $ua->proxy('http', 'http://127.0.0.1:9090/');

   $ua->default_header('X-Requested-With' => 'GSOC Qualys Script');  
#   $ua->show_progress(1);

   $ua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');
   my $sidres = $ua->request($sidreq);
   if ($sidres->is_success){
       my ($sid) = $sidres->content =~ /SID=(\d+)\+/;
       my $createnewurl = "http://servicedesk_url_changethis/CAisd/pdmweb.exe" . "?SID=" . $sid . '+FID=5561+OP=CREATE_NEW+FACTORY=cr+KEEP.IsPopUp=1+PRESET=priority%3A3+KEEP.POPUP_NAME=USD1378784730779+KEEP.use_role=1';
       $ua->default_header('Referer' => "http://servicedesk_url_changethis/CAisd/html/popup_frames.html?POPUP_URLIX=0+popupType=1");   
       my $createnewreq = HTTP::Request->new(GET => $createnewurl);
       my $createnewres = $ua->request($createnewreq);   
       
       
           my ($fid) = $createnewres->content =~ /var\s*cfgFID\s*=\s*\"(\d+)\"/;
           my ($ticketno) = $createnewres->content =~ /var\s*hdrTitleNew\s*=\s*\"Create\s*New\s*Request\s*(\d+)\"/;
           my ($persid) = $createnewres->content =~ /var\s*argPersistentID\s*=\s*\"(cr:\d+)\"/;
           my ($authorid) = $createnewres->content =~ /var\s*argCstID\s*=\s*\"(\w+)\"/;
           my ($popupname) = $createnewres->content =~ /var\s*argPopupName\s*=\s*\"(\w+)\"/;
           
           while (!defined $fid){
              say "CREATE NEWRES FAILED. RETRYING EVERY ONE SECOND";
              sleep 1;
              $createnewres = $ua->request($createnewreq); 
              ($fid) = $createnewres->content =~ /var\s*cfgFID\s*=\s*\"(\d+)\"/;
              ($ticketno) = $createnewres->content =~ /var\s*hdrTitleNew\s*=\s*\"Create\s*New\s*Request\s*(\d+)\"/;
              ($persid) = $createnewres->content =~ /var\s*argPersistentID\s*=\s*\"(cr:\d+)\"/;
              ($authorid) = $createnewres->content =~ /var\s*argCstID\s*=\s*\"(\w+)\"/;
              ($popupname) = $createnewres->content =~ /var\s*argPopupName\s*=\s*\"(\w+)\"/;
          }
           
           
# POST REQUEST FOR TICKET CREATION

        my $submitreq = HTTP::Request->new(POST => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe');
        $submitreq->content_type('application/x-www-form-urlencoded');

    

       if ($type eq 'child'){

#my $desc_buffer = 3000 - (length($$content[4]) + length($$content[5]) + length($$content[10]) + length($$content[6]));


        my ($fid) = $createnewres->content =~ /var\s*cfgFID\s*=\s*\"(\d+)\"/;
        my ($ticketno) = $createnewres->content =~ /var\s*hdrTitleNew\s*=\s*\"Create\s*New\s*Request\s*(\d+)\"/;
        my ($persid) = $createnewres->content =~ /var\s*argPersistentID\s*=\s*\"(cr:\d+)\"/;
        my ($authorid) = $createnewres->content =~ /var\s*argCstID\s*=\s*\"(\w+)\"/;
        my ($popupname) = $createnewres->content =~ /var\s*argPopupName\s*=\s*\"(\w+)\"/;
        my $server_ip = $external_mappings{$$content[0]} || $vip_mappings{$$content[0]} || 'VIP: Not Available SERVER IP: Not Available';
        my $summary = "PCI-DSS Vulnerability Scan for $$content[0] - \"$$content[2]\"  - $$content[16]";
        my $result = trim_description($$content[4], 'result', $$content[0], \$ua, $sid, $fid, $persid, $authorid, $popupname);
        my $impact = trim_description($$content[5], 'impact', $$content[0], \$ua, $sid, $fid, $persid, $authorid, $popupname);
        my $vendorref = trim_description($$content[10], 'reference', $$content[0], \$ua, $sid, $fid, $persid, $authorid, $popupname);
        my $issue = trim_description($$content[3], 'issue', $$content[0], \$ua, $sid, $fid, $persid, $authorid, $popupname);
        my $solution = trim_description($$content[6], 'solution', $$content[0], \$ua, $sid, $fid, $persid, $authorid, $popupname);
        my $correlation = trim_description($$content[18], 'exploit', $$content[0], \$ua, $sid, $fid, $persid, $authorid, $popupname);
        my $cveid = trim_description($$content[11], 'cveid', $$content[0], \$ua, $sid, $fid, $persid, $authorid, $popupname);
        my $criticality = get_impact($$content[8], 'impact', $$content[18]); 



my $description = <<"TICKETDESC";
Information Security Monitoring & Response Team (gsoc\@My.Co.com) has done a vulnerability scan on host $$content[0]. In order to remain compliant with PCI - Data Security Standards, it is important that the issue described below is addressed immediately.

If you are the owner of the system or host mentioned here, and you think such is an acceptable risk, please log your comment into this ticket. And if you believe that no fix is necessary, please attach a corresponding proof of the same. 



IP ADDRESS/PORT: $$content[0]:$$content[15] $server_ip
REGION: $$content[1]
OPERATING SYSTEM: $$content[7]
CVSS BASE: $$content[8]
PCI VULNERABILITY?: $$content[9]
IMPACT RATING:  $criticality


ISSUE>>>:
-------------
$issue



IMPACT>>>:
---------------
$impact



RECOMMENDED SOLUTION>>>:
-------------------------------------
$solution



TEST RESULT>>>:
---------------------- 
$result



ADDITIONAL INFORMATION>>>:
--------------------------------------
CVEID: $cveid
BUGTRAQ: $$content[12]
VENDOR REFERENCE: $$content[10]
EXPLOIT INFORMATION: $correlation



TICKETDESC


my $desclength = length($description);

if ($desclength > 4000){
        print "DESCRIPTION EXCEEDED 4000. $desclength TICKET $ticketno NOT CREATED. \"$$content[2]\"\n";
        #print LOGFILE "DESCRIPTION EXCEEDED 4000. $desclength TICKET $ticketno NOT CREATED. \"$$content[2]\"\n";


}


$description = expand($description);
$description = uri_escape($description);
$summary = uri_escape($summary); 
 
if (defined $custom_assignee_group){
   $assignee_group_hash = get_group_id(\$custom_assignee_group, \$ua, \$username, \$password);
   if (not defined $assignee_group_hash){
      $custom_assignee_group = undef;
      $assignee_group_hash = get_group_id(\$assignee_group, \$ua, \$username, \$password);
   } 
}else{
   $assignee_group_hash = get_group_id(\$assignee_group, \$ua, \$username, \$password);
}

 
   
my $request_content = 
'JEDIT=1' . 
'&SID=' . $sid . 
'&FID=' . $fid . 
'&OP=UPDATE' . 
'&FACTORY=cr' .
'&SET.id=0' . 
'&SET.zold_assignee=' . 
'&SET.zyes_no=0' . 
'&SET.z_l1_yes=1' . 
'&change_category=0' .
'&SET.call_back_flag=0' . 
'&NEW_ATTMNTS=' . 
'&customer_combo_name=' .
'&KEY.customer=' . $cfg->param("affected_customer") . 
'&customer_lname=' .  
'&customer_fname=' .  
'&customer_mname=' . 
'&SET.customer=' . 
'&SET.z_yes_no=No+Update+Required' .
'&SET.zphone_number=' . 
'&KEY.zlocation=' . 
'&SET.zlocation=' . 
'&KEY.zdept=' . 
'&SET.zdept=' . 
'&SET.zcr_room_location=' . 
'&SET.zcr_work_days=' . 
'&SET.zcr_work_hours=' . 
'&zcr_supervisor_combo_name=' . 
'&KEY.zcr_supervisor=' . 
'&zcr_supervisor_lname=' . 
'&zcr_supervisor_fname=' . 
'&zcr_supervisor_mname=' . 
'&SET.zcr_supervisor=' . 
'&SET.zcr_supervisor_phone=' . 
'&group_combo_name=' . (defined $custom_assignee_group?$custom_assignee_group:$assignee_group) . 
'&KEY.group=' . (defined $custom_assignee_group?$custom_assignee_group:$assignee_group) . 
'&group_lname=' . (defined $custom_assignee_group?$custom_assignee_group:$assignee_group) . 
'&group_fname=' . 
'&group_mname=' . 
'&SET.group=' . $assignee_group_hash . 
'&KEY.category=' . $request_area . 
'&SET.category=pcat%3A400974' . 
'&KEY.affected_resource=' . 
'&SET.affected_resource=' . 
'&SET.priority=3' . 
'&SET.summary=' . $summary . 
'&timer=' . 
'&SET.description=' . $description . 
'&assignee_combo_name=' . 
'&KEY.assignee=' . 
'&assignee_lname=' . 
'&assignee_fname=' . 
'&assignee_mname=' . 
'&SET.assignee=' . 
'&SET.status=OP' . 
'&SET.zrequest_pending_reason=' . 
'&SET.zescalated=' . 
'&SET.zspecial_handling=0' . 
'&SET.call_back_date=' . 
'&SET.call_back_date_INT_DATE=0' . 
'&SET.zyes_related_request=0' . 
'&KEY.zrelated_request=' . 
'&SET.zrelated_request=' . 
'&SET.zyes_related_incident=0' . 
'&KEY.zrelated_incident=' . 
'&SET.zrelated_incident=' . 
'&SET.zyes_related_change=0' . 
'&KEY.caused_by_chg=' .
'&SET.caused_by_chg=' . 
'&SET.zyes_related_problem=0' . 
'&KEY.problem=&SET.problem=' . 
'&KEY.rootcause=' . 
'&SET.rootcause=' . 
'&catg_cawf_defid=' . 
'&SET.ztel_prod_supp_date=' . 
'&SET.template_name=' . 
'&SET.template_name.template_class=' . 
'&SET.template_name.quick_tmpl_type=0' . 
'&SET.template_name.delete_flag=0' . 
'&SET.template_name.description=' . 
'&KEY.parent=' . 
'&SET.parent=' . 
'&SET.catg_cawf_defid2=' . 
'&category_contract=' . 
'&user_contract=0' . 
'&org_id=';


$submitreq->content($request_content);
$submitreq->content_length(length($request_content));


  }
    


my $submitres = $ua->request($submitreq);
my $posttimeout = 0; 
while (!$submitres->is_success){
   say "Sending post request for ticket creation failed. Retrying after 2 seconds";
   sleep 2;
   $posttimeout += 2;
   $submitres = $ua->request($submitreq);
   last if $posttimeout == 120;
}

 if ($submitres->is_success){
    ++$allticketcounter;
    ($persid) = $persid =~ /cr:(\d+)$/;
    print "$allticketcounter) Ticket $ticketno created for " . "$$content[0]:$$content[15] - " . ($type eq 'child'?"\"$$content[2]\"":$content) . " (QBE.EQ.id=$persid)", "\n";
   # print LOGFILE "$allticketcounter) Ticket $ticketno created for " . "$$content[0]:$$content[15] - " . ($type eq 'child'?"\"$$content[2]\"":$content) . " (http://servicedesk_url_changethis/CAisd/pdmweb.exe?OP=SEARCH+FACTORY=cr+SKIPLIST=1+QBE.EQ.id=$persid)", "\n";
    return $ticketno, $persid;
 }else{

     print "FAILED CREATING TICKET $ticketno", "\n\n", $submitres->content, "\n";
    # print LOGFILE "FAILED CREATING TICKET $ticketno", $submitres->content, "\n";
     print "REQUEST SENT WAS " . $submitreq->content, "\n";
    # print LOGFILE "REQUEST SENT WAS " . $submitreq->content, "\n";
    # print LOGFILE scalar localtime;
     exit;
 }

     
#    }else{
#      say "CREATE NEWRES FAILED";
#    }
  
   }else{

         print "AUTHENTICATION FAILED ON TICKET CREATION!!!. EXITING...\n\n";
         say $sidres->content;
       #  print LOGFILE "AUTHENTICATION FAILED ON TICKET CREATION!!!. EXITING...\n";
       #  print LOGFILE scalar localtime;
         exit;
        }

}


#################################################################################

sub get_group_id{
   my $group = shift @_;
   my $ua = shift @_;
   my $username = shift @_;
   my $password = shift @_;   
   $$ua->cookie_jar({});
   $$ua->proxy('http', 'http://127.0.0.1:9090/');
   my $assignee_group = $$group;
   $assignee_group =~ s/\s+/\%20/g;
   $$ua->default_header('X-Requested-With' => 'Perl Script');  
   $$ua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');
   my $sid = get_sid($ua, $username, $password);
   my $url = 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '&FID=7365+OP=SEARCH+FACTORY=cnt+KEEP.IsPopUp=1+KEEP.backfill_field=group+KEEP.backfill_form=main_form+KEEP.Is3FieldContact=1+KEEP.domset_name=RLIST_STATIC+KEEP.type.id=2308+QBE.EQ.delete_flag=0+numAutosuggestRecords=25+common_name=combo_name&QBE.IN.last_name=' . $assignee_group;
   my $grouphashreq = HTTP::Request->new(GET => $url);
   my $grouphashres = $$ua->request($grouphashreq);  
   if ($grouphashres->is_success){
      (my $grouphash) = $grouphashres->content() =~ /\"id\":\s+\"(.*)\",/;
      if (defined $grouphash){
         return $grouphash;
      }else{
         say "CUSTOM ASSIGNEE GROUP $$group WAS NOT FOUND. DEFAULTING TO IT SECURITY MONITORING GLOBAL";
         return undef;
      }
   }else{
      say "UNABLE TO RETRIEVE INFO FOR ASSIGNEE GROUP $$group. CHECK YOUR CONNECTION";
      return undef;
   }


   
   
}

### ROUTINE FOR GETTING THE LIST OF ASSET GROUPS ASSIGNED TO qualys_username SPECIFIED IN THE CONFIG
sub get_asset_groups{
   my $regionindex = 1;
   my $qualysua = new LWP::UserAgent(keep_alive => 1); 
   $qualysua->show_progress(1);
   $qualysua->cookie_jar({});
   $qualysua->default_header('X-Requested-With' => 'Perl Script');  
   $qualysua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');

   my %asset_groups;
   my $assetgroupreq = HTTP::Request->new(GET => 'https://qualysapi.qualys.com/msp/asset_group_list.php');
   $assetgroupreq->authorization_basic($qualysusername, $qualyspassword); 
   my $assetgroupres = $qualysua->request($assetgroupreq);

   if ($assetgroupres->header('X-RateLimit-Remaining') == 0){
       print "\nasset_group_list.php was blocked. API calls left is " . $assetgroupres->header('X-RateLimit-Remaining') . ".", "\n";
       my $errorparser = XML::LibXML->new();   
       my $errormessage  = $errorparser->parse_string($assetgroupres->content());
       my @errors = $errormessage->findnodes('/SIMPLE_RETURN');
       foreach (@errors){
          my $error = $_->findvalue('RESPONSE/TEXT');
          chomp $error;
          $error =~ s/^\s+//;
          $error =~ s/\s+$//;
          print "\nServer says: \n\n  \"$error\"", "\n\n\n";      
      }
      exit;
   }else{
      say  "\n***  " . $assetgroupres->header('X-RateLimit-Remaining') . " API calls left. Approximately " . int($assetgroupres->header('X-RateLimit-Remaining') / 7) . " runs of this script.   ***\n\n\n";
   }

   if ($assetgroupres->is_success){  
        my $assets = XMLin($assetgroupres->content(), ForceArray => ['IP']);
        foreach my $region(@{$assets->{ASSET_GROUP}}){
	    next if $region->{TITLE} eq 'All';
	    foreach my $ip(keys %{$region->{SCANIPS}}){
		foreach (@{$region->{SCANIPS}{$ip}}){
		    push @{$asset_groups{$regionindex}{$region->{TITLE}}{IPs}}, $_;
		}
	    }
	    $asset_groups{$regionindex}{$region->{TITLE}}{LAST_UPDATE} = $region->{LAST_UPDATE};
            ++$regionindex;
        }

   }else{
      print "AUTHENTICATION FAILED OR BAD CONNECTION WHILE RETRIEVING ASSET GROUPS.\n";
      print $assetgroupres->content();
   } 
   

   return %asset_groups; 
   
}






####################################
### ROUTINE FOR GETTING A LIST OF SCAN RESULTS FOR EACH SELECTED REGION

sub get_scanresult{
   
    my $targets = shift;
    my $region = shift;
    my $ua = new LWP::UserAgent(keep_alive => 1); 
    $ua->show_progress(1) if $debug eq 'yes';
    my $parser = XML::LibXML->new();
    $ua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');
    $ua->cookie_jar({});
    $ua->default_header('X-Requested-With' => 'Perl Script'); 
    my $resultreq = HTTP::Request->new(POST => 'https://qualysapi.qualys.com/api/2.0/fo/scan/');
    $resultreq->authorization_basic($qualysusername, $qualyspassword); 
    $resultreq->content_type('application/x-www-form-urlencoded');
    my $resultreqcontent;
    if (!defined $target_date or ref $target_date){
       $resultreqcontent = 'action=list&state=Finished&show_ags=1&target=' . $targets . ($scanner_account ne ''?'&user_login=' . $scanner_account:'');
    }else{
       $resultreqcontent = 'action=list&launched_before_datetime=' . $target_date . '&state=Finished&show_ags=1&target=' . $targets . ($scanner_account ne ''?'&user_login=' . $scanner_account:'');
    }
    $resultreq->content($resultreqcontent);


    my $resultres = $ua->request($resultreq);

    
    if (defined $resultres->header('X-RateLimit-Remaining') && $resultres->header('X-RateLimit-Remaining') == 0){
        print "\nCall to scan/ - resultreq was blocked. API calls left is " . $resultres->header('X-RateLimit-Remaining') . ".",  "\n";
        my $errorparser = XML::LibXML->new();   
        my $errormessage  = $errorparser->parse_string($resultres->content());
        my @errors = $errormessage->findnodes('/SIMPLE_RETURN');
        foreach (@errors){
            my $error = $_->findvalue('RESPONSE/TEXT');
            chomp $error;
            $error =~ s/^\s+//;
            $error =~ s/\s+$//;
            print "\nServer says: \n\n  \"$error\"", "\n\n\n";
        }
 
        exit;
    }

    if ($resultres->is_success){ 
       
       
              my $scanlistparser = XML::LibXML->new();   
                     my $validxml = eval {
                        $scanlistparser->parse_string($resultres->content());
                     }; 
               if (!$validxml){
                     say "\n** XML SCAN LIST OUTPUT FOR $$region IS MALFORMED. CONTACT QUALYS TO FIND OUT WHY. SKIPPING...  **\n";
                     return;
               }
       
       
       
          my $scanlist = $parser->parse_string($resultres->content());
          my @scannodes = $scanlist->findnodes('/SCAN_LIST_OUTPUT/RESPONSE/SCAN_LIST/SCAN');
          my %scanlist;
          foreach (@scannodes){
             
             
#THIS WILL LIST DOWN ONLY THE SCAN RESULTS WHERE THE TARGET SPECIFIED IS AN ASSET GROUP. COMMENT OUT IF YOU WANT TO INCLUDE SCAN RESULTS WHERE TARGETS ARE NOT ASSET GROUPS.
#skip random targets (for validation of remediation)
#SKIP SCAN RESULT IF ASSET GROUP DOES NOT MATCH THE REGION

       unless ($process_anontargets eq 'yes'){
          my $embedded_title = $_->findvalue('ASSET_GROUP_TITLE_LIST/ASSET_GROUP_TITLE');
#IF THE CURRENT ASSET GROUP'S NAME IS DIFFERENT FROM THE NAME EMBEDDED IN A PREVIOUS REPORT (E.G., WHEN RENAMED), THE SCRIPT WILL NOT PROCESS THAT SCAN RESULT. THEY CAN BE FIXED HERE.
          $embedded_title = 'My.Co Japan - Site1' if $embedded_title eq 'My.Co Japan-Site1';
          $embedded_title = 'My.Co China External' if $embedded_title eq 'My.Co China' or $embedded_title eq 'China External';

          next if $embedded_title eq ''; 
          next if $embedded_title ne $$region; 
       }   
### SAVE THE DATE AND SCAN REF TO %scanlist                    
#          $scanlist{$_->findvalue('REF')} = $_->findvalue('LAUNCH_DATETIME');
           $scanlist{$_->findvalue('REF')}{LAUNCHDATE} = $_->findvalue('LAUNCH_DATETIME');
 #          $scanlist{$_->findvalue('REF')}{TITLE} = $_->findvalue('TITLE');
           
          print " " , $_->findvalue('REF') . ' :: ' . $_->findvalue('LAUNCH_DATETIME') . ' :: ' . '(' . ((defined $_->findvalue('ASSET_GROUP_TITLE_LIST/ASSET_GROUP_TITLE') && $_->findvalue('ASSET_GROUP_TITLE_LIST/ASSET_GROUP_TITLE') ne '')?$_->findvalue('ASSET_GROUP_TITLE_LIST/ASSET_GROUP_TITLE'):$_->findvalue('TITLE')) . ')' . "\n";
     }
 
 
       
          my $counter = 0;
          my $max_results = $cfg->param("max_scan_results");
          $max_results = 4 if (!defined $max_results || ref($max_results));
          my @scanrefs;
          foreach (sort { (str2time($scanlist{$b}{LAUNCHDATE}) <=> str2time($scanlist{$a}{LAUNCHDATE})) } keys %scanlist){
             last if $counter == $max_results;
### PROCESS ONLY SCAN RESULTS FOR THE MONTH INDICATED BY $monthfilter
            if (!ref $monthfilter){  
                next unless DateTime::Format::ISO8601->parse_datetime($scanlist{$_}{LAUNCHDATE})->strftime('%m/%d/%Y') =~ /^$monthfilter\/\d+\//;
             }               
                
	        push @scanrefs, [$_, DateTime::Format::ISO8601->parse_datetime($scanlist{$_}{LAUNCHDATE})->strftime('%m/%d/%Y')];
	        ++$counter;
          }    
          
         my ($currentxml, $secondxml, $thirdxml, $fourthxml);

          print " - Latest   (" . (defined $scanrefs[0][0]?DateTime::Format::ISO8601->parse_datetime($scanlist{$scanrefs[0][0]}{LAUNCHDATE})->strftime('%m/%d/%Y(%Z)') . " : " . $scanrefs[0][0]:'Not found') . ")\n";
          $currentxml = get_xmlreport($scanrefs[0][0], $ua);
          print " - Previous (" . (defined $scanrefs[1][0]?DateTime::Format::ISO8601->parse_datetime($scanlist{$scanrefs[1][0]}{LAUNCHDATE})->strftime('%m/%d/%Y(%Z)') . " : " . $scanrefs[1][0]:'Not found') . ")\n"; 
          $secondxml = get_xmlreport($scanrefs[1][0], $ua);
          $thirdxml = get_xmlreport($scanrefs[2][0], $ua);
          $fourthxml = get_xmlreport($scanrefs[3][0], $ua);
          
         
          
          
          if (!defined $currentxml){  
               return;           
          }
          
          return ($currentxml, $secondxml, $thirdxml, $fourthxml, $scanrefs[0][0], $scanrefs[0][1], $scanrefs[1][1], $scanrefs[2][1], $scanrefs[3][1] ); 
          
     }else{   
          print "WEB REQUEST FAILED\n";
          print $resultres->content();
          exit;
     }
}





###########################################################
### ROUTINE THAT WILL DOWNLOAD THE CORRESPONDING XML SCAN RESULTS LISTED IN sub get_scanresult

sub get_xmlreport{
   
   my $xmlfolder = $cfg->param("xml_folder");
   my $ref = shift;
   my $xmlfile = $ref . '.xml' if defined $ref;
   my $destxml;
   
### THERE IS REF, $XMLFOLDER ISN'T BLANK, AND $XMLFOLDER IS LOCAL   
     unless (!defined $ref){
        if (!ref($xmlfolder) && $xmlfolder eq 'local'){
           $xmlfolder = $sourcefolder . 'xml scan results';
           unless (-e $xmlfolder && -d $xmlfolder){
                mkdir $xmlfolder or (die "Unable to create local xml folder. Check your permission on $xmlfolder\n");
           }               
       }
       
           (my $newxmlfile = $xmlfile) =~ s/\//_/;
           $newxmlfile =~ s/\./_/g;
           $newxmlfile =~ s/_xml/\.xml/;   
           $destxml = $xmlfolder . "\\" . $newxmlfile;    
              
       
### LOOK FOR ALL XML SCAN RESULT IN $XMLFOLDER THEN SAVE THEM IN %SAVEDXMLFILES     
          my %findopts = (follow_skip => 2, wanted => \&wantedxml);
          find(\%findopts, $xmlfolder);
          
          if (exists $savedxmlfiles{$xmlfile}){               
                     my $savedparser = XML::LibXML->new();   
                     my $validxml = eval {
                        $savedparser->parse_file($savedxmlfiles{$xmlfile});
                     }; 
               if (!$validxml){
                     say "\n** XML SCAN RESULT $ref IS MALFORMED. CONTACT QUALYS TO FIND OUT WHY. SKIPPING...  **\n";
                     return(undef);
               }else{
                    return \$savedxmlfiles{$xmlfile};
               }
          }
   }


### IF XML HAS NOT BEEN DOWNLOADED YET

   my $ua = shift @_;
   $ua->show_progress('true value');
   $ua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');
   $ua->cookie_jar({});
   $ua->default_header('X-Requested-With' => 'Perl Script'); 

   if (not defined $ref){
      return (undef);
   }
   my $xmlurl = 'https://qualysapi.qualys.com/msp/scan_report.php?ref=' . $ref;   
   my $content_file = $destxml;  
   my $fetchreq = HTTP::Request->new(GET => $xmlurl);
   $fetchreq->authorization_basic($qualysusername, $qualyspassword); 
   my $fetchres = $ua->request($fetchreq, $content_file);
   

   if ($fetchres->is_success){      
      if ($fetchres->header('X-RateLimit-Remaining') == 0){
          print "\nCall to scan_report.php was blocked. API calls left is " . $fetchres->header('X-RateLimit-Remaining') . ".", "\n";
          my $errorparser = XML::LibXML->new();   
          my $errormessage  = $errorparser->parse_string($fetchres->content());
          my @errors = $errormessage->findnodes('/SIMPLE_RETURN');
          foreach (@errors){
             my $error = $_->findvalue('RESPONSE/TEXT');
             chomp $error;
             $error =~ s/^\s+//;
             $error =~ s/\s+$//;
             print "\nServer says: \n\n  \"$error\"", "\n\n\n";
          }
     
      exit;  
      }
     
     my $downloadedparser = XML::LibXML->new(); 
     my $validxml = eval {
         $downloadedparser->parse_file($destxml);
      };     
     if (!$validxml){
        say "\n** XML SCAN RESULT $ref IS MALFORMED. CONTACT QUALYS TO FIND OUT WHY. SKIPPING...  **\n";
        return(undef);
     }else{
        return \$destxml;
    }
   }else{
      exit;
   }
}

######################################################################


sub wantedxml {

                     if (! -d $_ && $_ =~ /scan_\d+_\d+\.xml$/){
                          (my $xml) = $_ =~ /(scan_\d+_\d+\.xml)/;             
                          $xml =~ s/scan_/scan\//;
                          $xml =~ s/_/\./g;
                          $savedxmlfiles{$xml} = $File::Find::name;    
                      } 
          }


#####################################

## ROUTINE FOR TRIMMING THE DETAILS OF A VULNERABILITY THAT WILL GO INTO THE SD TICKET DESCRIPTION WHICH HAS A LIMIT OF 4000 CHARACTERS. ANY EXCESS WILL GO TO A TEXT FILE ATTACHMENT.
 
sub trim_description{

   my $content = shift @_;
   my $type = shift @_;
   my $host = shift @_;
   my $ua = shift @_;
   my $sid = shift @_;
   my $fid = shift @_;
   my $persid = shift @_;
   my $authorid = shift @_;
   my $popupname = shift @_;
   my $maxlen;
  # $$ua->show_progress(1);
   $content =~ s/\R{3,}/\n\n/g;           
   $content =~ s/^\s*$//g;
   $content = decode_entities($content);
   $content =~ s/\n{3,}/\n\n/g;
   $content =~ s/\<P\>//g;
   $content =~ s/\<BR\>//g;


   $maxlen = 800 if $type eq 'issue';
   $maxlen = 300 if $type eq 'impact';
   $maxlen = 200 if $type eq 'result';
   $maxlen = 500 if $type eq 'solution';
   $maxlen = 300 if $type eq 'reference';
   $maxlen = 300 if $type eq 'exploit';
   $maxlen = 50 if $type eq 'cveid';


   if (length($content) > $maxlen){
      
      my $trimmed = substr $content, 0, $maxlen;
      $trimmed = substr ($trimmed, 0, rindex($trimmed, "\n"));

      my $attachmentname = $host . '_' . $type . '.txt';
      $trimmed = $trimmed . "\n\n__output trimmed__\n\n(Please see the attached " . $attachmentname . " to view the full details of the $type.)";
      open TRIMMED, "> $attachmentname" or die $!;
      print TRIMMED $content;
      close TRIMMED;


# UPLOAD EMPTY FOLDER?               
$$ua->post(
  'http://servicedesk_uploadserver_changethis:8080/CAisd/UploadServlet',
   ['inpDocRepository' => 'doc_rep:1002',
    'inpFileUpload' => [undef, undef , 'Content_Type' => 'application/octet-stream'],
    'inpAttName' => '',
    'inpDesc'    => '',
    'inpRetURL' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=6169+OP=DISPLAY_FORM+HTMPL=attmnt_upload_done.htmpl+KEEP.AttmntParent=' . $persid,
    'Test' => '1',
    'inpServerName' => '',
    'inpMaxFileSize' => '',
    'inpBpsid' => '',        
  ],
  'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1',
  'Content_Type' => 'multipart/form-data'
);


# KEEP FILE UPLOAD
my $keepfileupload;
$keepfileupload = $$ua->get('http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1063+FACTORY=attmnt+KEEP.FILE_UPLOAD=1+PRESET=link_only:0+KEEP.POPUP_NAME=' . $popupname . '+HTMPL=detail_kt_attmnt_edit.htmpl+RO_HTMPL=detail_attmnt_ro.htmpl+KEEP.PARENT_PERSID=' . $persid . '+attmnt_parent=cr+OP=CREATE_NEW+PRESET=link_only:0+PRESET=repository:doc_rep:1002',
'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1'
);

my ($uploadfid, $attachid, $uuid);
($uploadfid) = $keepfileupload->content =~ /var\s*cfgFID\s*=\s*\"(\d+)\"/;
($attachid) = $keepfileupload->content =~ /var\s*argPersistentID\s*=\s*\"attmnt:(\d+)\"/;
($uuid) = $keepfileupload->content =~ /parent\.SetDobId\(\"\d+\",\"(\w+)\"\)/;

while ((!defined $uploadfid && !defined $attachid) && !defined $uuid){
   say "UNABLE TO INITIATE ATTACHMENT UPLOAD. RETRYING AFTER 1 SECOND..." if $debug eq 'yes';
   sleep 1;
   $keepfileupload = $$ua->get('http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1063+FACTORY=attmnt+KEEP.FILE_UPLOAD=1+PRESET=link_only:0+KEEP.POPUP_NAME=' . $popupname . '+HTMPL=detail_kt_attmnt_edit.htmpl+RO_HTMPL=detail_attmnt_ro.htmpl+KEEP.PARENT_PERSID=' . $persid . '+attmnt_parent=cr+OP=CREATE_NEW+PRESET=link_only:0+PRESET=repository:doc_rep:1002',
   'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1'
  );
  ($uploadfid) = $keepfileupload->content =~ /var\s*cfgFID\s*=\s*\"(\d+)\"/;
  ($attachid) = $keepfileupload->content =~ /var\s*argPersistentID\s*=\s*\"attmnt:(\d+)\"/;
  ($uuid) = $keepfileupload->content =~ /parent\.SetDobId\(\"\d+\",\"(\w+)\"\)/;
}


# UPLOAD DONE
my $uploadfolderdone = $$ua->get('http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=6169+OP=DISPLAY_FORM+HTMPL=attmnt_upload_done.htmpl+KEEP.AttmntParent=' . $persid . '+Test=1',
'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1'
);



# KT OPEN SESSION
my $opensessionurl = 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=7407+OP=KT_OPEN_REP_SESSION+Keep=1+AttmntId=0+FolderId=0+Host=SERVICEDESK_UPLOADSERVER_CHANGETHIS+FileName=' . $attachid . '_' . $attachmentname . '+RepId=doc_rep:1002';
my $ktopenrepsession = $$ua->get($opensessionurl,'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1');
my ($inpbpsid) = $ktopenrepsession->content =~ /msg\[1\]=\'(\d+)\'/;
my ($zipfilename) = $ktopenrepsession->content =~ /msg\[2\]=\'(.*?)\'/;
my ($repfolder) = $ktopenrepsession->content =~ /msg\[3\]=\'(\w+)\'/;
my ($docrep) = $ktopenrepsession->content =~ /msg\[4\]=\'(.*?)\'/;
my $attachmentfullpath = $sourcefolder . $attachmentname;
my $ktretries = 0;

while (!defined $inpbpsid && !defined $docrep){
   say "UNABLE TO GET INPBPSID AND DOCREP IN KT OPEN SESSION. RETRYING EVERY 1 SECOND..." if $debug eq 'yes';
   sleep 1;
   $ktopenrepsession = $$ua->get($opensessionurl,'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1');
   ($inpbpsid) = $ktopenrepsession->content =~ /msg\[1\]=\'(\d+)\'/;
   ($zipfilename) = $ktopenrepsession->content =~ /msg\[2\]=\'(.*?)\'/;
   ($repfolder) = $ktopenrepsession->content =~ /msg\[3\]=\'(\w+)\'/;
   ($docrep) = $ktopenrepsession->content =~ /msg\[4\]=\'(.*?)\'/;
   $attachmentfullpath = $sourcefolder . $attachmentname;
}


# UPLOAD ATTACHMENT
$$ua->post(
  'http://servicedesk_uploadserver_changethis:8080/CAisd/UploadServlet',
   ['inpDocRepository' => $docrep,
    'inpFileUpload' => [$attachmentfullpath, $attachmentfullpath, 'Content_Type' => 'text/plain'],
    'inpAttName' => $attachmentname,
    'inpDesc'    => 'contains full details of the ' . $type,
    'inpRetURL' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=6169+OP=DISPLAY_FORM+HTMPL=attmnt_upload_done.htmpl+KEEP.AttmntParent=' . $persid,
    'Test' => '',
    'inpServerName' => 'SERVICEDESK_UPLOADSERVER_CHANGETHIS',
    'inpMaxFileSize' => 0,
    'inpBpsid' => $inpbpsid,        
  ],
  'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1',
  'Content_Type' => 'multipart/form-data'
);





# KEEP ALIVE REQUEST
my $keepalive = $$ua->get('http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1+OP=KEEP_ALIVE+REP_PROCID=rep_daemon:SERVICEDESK_UPLOADSERVER_CHANGETHIS+REP_SESSION=' . $inpbpsid,
'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=7407+OP=KT_OPEN_REP_SESSION+Keep=1+AttmntId=0+FolderId=0+Host=SERVICEDESK_UPLOADSERVER_CHANGETHIS+FileName=' . $attachid . '_' . $attachmentname . '+RepId=doc_rep:1002'
);



# UPLOAD ATTACHMENT DONE
my $uploadattachmentdone = $$ua->get('http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=6169+OP=DISPLAY_FORM+HTMPL=attmnt_upload_done.htmpl+KEEP.AttmntParent=' . $persid . '+ErrorCode=0+RelFilePath=' . $repfolder . '+FileSize=44+KEEP.success_str=Directory: ' . $sourcefolder . ', File Name: ' . $attachmentfullpath . ', File Upload Successful!!!',
'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1515+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1'
);

# CLEAN UP, DELETE ATTACHMENT IN THE CURRENT DIR
#print "DELETING $attachmentfullpath\n";
#sleep 10;
unlink $attachmentfullpath;


# POST REQUEST TO LINK ATTACHMENT TO THE TICKET
$$ua->post(
  'http://servicedesk_url_changethis/CAisd/pdmweb.exe',
   ['JEDIT' => 1,
    'SID' => $sid,
    'FID' => $uploadfid,
    'OP' => 'UPDATE',
    'FACTORY' => 'attmnt',
    'SET.id' => 0,
    'SET.attmnt_name' => $attachmentname,
    'SET.orig_file_name' => $attachmentname,
    'SET.file_name' => $zipfilename,
    'SET.rel_file_path' => $repfolder,
    'SET.file_size' => 44,
    'SET.file_type' => 'txt',
    'SET.zip_flag' => 1,
    'SET.created_by' => $authorid,
    'SET.last_mod_by' => $authorid,
    'SET.status' => 'INSTALLED',
    'SET.link_only' => 0,
    'SET.description' => 'contains full details of the ' . $type,
    'SET.submit_knowledge' => 0,
    'SET.sec_uuid' => $uuid,
    'SET.repository' => $docrep,
    'KEEP.parent_persid' => $persid,
    'KEEP.lrel_name' => 'attachments'       
  ],
  'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=1063+FACTORY=attmnt+KEEP.FILE_UPLOAD=1+PRESET=link_only:0+KEEP.POPUP_NAME=' . $popupname . '+HTMPL=detail_kt_attmnt_edit.htmpl+RO_HTMPL=detail_attmnt_ro.htmpl+KEEP.PARENT_PERSID=' . $persid . '+attmnt_parent=cr+OP=CREATE_NEW+PRESET=link_only:0+PRESET=repository:' . $docrep,
  'Content_Type' => 'application/x-www-form-urlencoded'
);




# KT CLOSE SESSION
my $ktclosesession = $$ua->get('http://servicedesk_url_changethis//CAisd/pdmweb.exe?SID=' . $sid . '+FID=7848+OP=KT_CLOSE_REP_SESSION+Host=SERVICEDESK_UPLOADSERVER_CHANGETHIS+SessionId=' . $inpbpsid,
'Referer' => 'http://servicedesk_url_changethis/CAisd/pdmweb.exe?SID=' . $sid . '+FID=2211+OP=DISPLAY_FORM+HTMPL=attmnt_upload_popup.htmpl+AttmntId=0+RepId=0+FolderId=0+View=Upload+ShowFields=Yes+ShowImgStatus=Yes+ShowRepList=Yes+RepType=0+KEEP.POPUP_NAME=' . $popupname . '+KEEP.PARENT_DIV=nbtab_1+KEEP.attmnt_parent=' . $persid . '+KEEP.use_role=1'
);


  return $trimmed;

}else{
   return $content;
}



}



### SIMULATE EXCEL's RUNTIME AUTOFIT FEATURE

sub autofit_columns {

    my $worksheet = shift;
    my $col       = 0;

    for my $width (@{$worksheet->{__col_widths}}) {

        $worksheet->set_column($col, $col, $width) if $width;
        $col++;
    }
}


sub get_impact{
   
   
  my $cvss_score = shift @_;
  my $type = shift @_;
  my $correlation = shift @_;
  
   
  if ($type eq 'impact'){
     if (defined $correlation && $correlation ne ''){
            return 'Emergency' if $cvss_score > 7;

      }else{
           return 'Critical' if $cvss_score > 7;
      }
     return 'Major' if $cvss_score >= 4 && $cvss_score <= 7;
     return 'Minor' if $cvss_score < 4;
  }
  if ($type eq 'ola'){
     if ( defined $correlation && $correlation ne ''){
         return '1' if $cvss_score > 7;

     }else{
         return '2' if $cvss_score > 7;
     }
     return '7' if $cvss_score >= 4 && $cvss_score <= 7;
     return '14' if $cvss_score < 4;
  }

}




sub qualys_session{
 
  my $type = shift @_;
  my $cookie_jar;
 
  my $ua = new LWP::UserAgent(keep_alive => 1); 
  if ($type eq 'login'){
    $cookie_jar = HTTP::Cookies->new( );
 }else{
    my $cookie_jar_ref = shift @_;
    $cookie_jar = $$cookie_jar_ref;
    
 }
  $ua->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; BRI/1; .NET4.0C; InfoPath.2; .NET4.0E; MALC)');
  $ua->cookie_jar( $cookie_jar );
  $ua->default_header('X-Requested-With' => 'Perl Script'); 
  
  
  my $sessionreq = HTTP::Request->new(POST => 'https://qualysapi.qualys.com/api/2.0/fo/session/');
  $sessionreq->content_type('application/x-www-form-urlencoded');
 
 if ($type eq 'login'){ 
       $sessionreq->content("action=login&username=$qualysusername&password=$qualyspassword");
  }else{
       $sessionreq->content("action=logout");

  }
  
  my $sessionres = $ua->request($sessionreq);
  
  my $sessionxmlparser = XML::LibXML->new(); 
  my $sessionxml = $sessionxmlparser->parse_string($sessionres->content());
  my @sessionres = $sessionxml->findnodes('/SIMPLE_RETURN');
  foreach (@sessionres){
            my $res = $_->findvalue('RESPONSE/TEXT');
            chomp $res;
            $res =~ s/^\s+//;
            $res =~ s/\s+$//;
            if (defined $cookie_jar){
               return(\$res, \$cookie_jar);
            }else{  
               return(\$res);
            }
   }
   
   
   
}


################################################################################

sub store_string_widths {

    my $worksheet = shift;
    my $col       = $_[1];
    my $token     = $_[2];




    # Ignore some tokens that we aren't interested in.
    return if not defined $token;       # Ignore undefs.
    return if $token eq '';             # Ignore blank cells.
    return if ref $token eq 'ARRAY';    # Ignore array refs.
    return if $token =~ /^=/;           # Ignore formula
    return if $token =~ /^\d+\.\)/;
    return if $token =~ /Scan Targets/;
    return if $token =~ /unverified/;
    return if $token =~ /^\s\d+\.\d+\.\d+\.\d+/;
    return if $token =~ /^CVE/;
    return if $token =~ /^\(/;
    return if $token eq 'Changes from the Previous Scans';

    # Ignore numbers
    return if $token =~ /^([+-]?)(?=\d|\.\d)\d*(\.\d*)?([Ee]([+-]?\d+))?$/;

    # Ignore various internal and external hyperlinks. In a real scenario
    # you may wish to track the length of the optional strings used with
    # urls.
    return if $token =~ m{^[fh]tt?ps?://};
    return if $token =~ m{^mailto:};
    return if $token =~ m{^(?:in|ex)ternal:};


    # We store the string width as data in the Worksheet object. We use
    # a double underscore key name to avoid conflicts with future names.
    #
    my $old_width    = $worksheet->{__col_widths}->[$col];
    my $string_width = string_width($token);
    $string_width = $string_width;
    
    if (not defined $old_width or $string_width > $old_width) {
        # You may wish to set a minimum column width as follows.
        #return undef if $string_width < 10;
        
        $worksheet->{__col_widths}->[$col] = $string_width;
        
    }


    # Return control to write();
    return undef;
}


###############################################################################
#
# Very simple conversion between string length and string width for Arial 10.
# See below for a more sophisticated method.
#
sub string_width {

    return 0.9 * length $_[0];
}
