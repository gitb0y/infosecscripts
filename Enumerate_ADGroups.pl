#!/usr/bin/perl

#################################################################################
#                                                                               #
# A program that takes a list of AD groups and enumerate each group's members.  #
# Author: Mark Alvarez                                                          #
# Usage: #perl Enumerate_ADGroups.pl                                            #
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




use 5.010;
use strict;
use warnings;
use Win32::OLE;
use Cwd;

my $rootdse=Win32::OLE->GetObject("LDAP://RootDSE") or die "CONNECTION TO SERVER FAILED. EXITING...", "\n\n";
my $basedn=$rootdse->Get("RootDomainNamingContext");
my $ldap_url="<GC://$basedn".">";
our $subgroup = 0;
our $usercount = 0;
our  %managers;

my $inputfile = getcwd . "\\groups.csv";
my $outputfile = getcwd . "\\group members.csv";
open GROUPMEMBERS, ">$outputfile" or die $!;
open GROUPS, "$inputfile" or die $!;


while (<GROUPS>){
  chomp;
  $_ =~ s/\s+$//;
  print "\n<<<<  \"$_\"  >>>>\n------------------------------------\n" if $subgroup == 0;
  print GROUPMEMBERS "\n<<<<  $_  >>>>\n" if $subgroup == 0;
  my $group = get_attribute("(cn=$_)", "", 'member', 'TRUE');
  if ($group eq 'NOT FOUND'){
      print "INVALID GROUP\n\n";
      next;
   }elsif ($group =~ /^UNABLE TO ACCESS/){
      print "SEARCH FAILED FOR $_. SKIPPING...\n";
      next;
   }
  get_members($group);
  print "TOTAL INDIVIDUAL MEMBERS OF \"$_\": $usercount\n_________________________________________\n-----------------------------------------\n\n\n\n";
  print GROUPMEMBERS "TOTAL INDIVIDUAL MEMBERS OF \"$_\": $usercount\n\n\n\n";
  $usercount = 0;
  $subgroup = 0; 
}


sub get_members{
  
   my $members = shift @_;
 
   for (@$members){
       chomp;
       (my $cname) = $_ =~ /^CN=(.*?),\w+=/;
       $cname =~ s/\\// unless ($cname =~ /^(!|_)/);     
       my $category = get_attribute('', $_, 'objectCategory');    
       
         if ($category eq 'CN=Group,CN=Schema,CN=Configuration,DC=mycompany_changethis,DC=com'){
             $subgroup = 1;      
             print GROUPMEMBERS  "\n<<<<  $cname  >>>>\n";
             print "\n<<<<  $cname  >>>>\n";
             my $members = get_attribute("", $_ , 'member', 'FALSE');   
             get_members ($members);
             
          }elsif ($category eq 'CN=Person,CN=Schema,CN=Configuration,DC=mycompany_changethis,DC=com'){                
               my $accountstatus = get_attribute("(userAccountControl:1.2.840.113556.1.4.803:=2)", $_, 'cn' );
               my $manager = 'NOT FOUND TO';
               my $mgremail = "";
               unless ($cname =~ /svc/i){
                    $manager = get_attribute("", $_, 'manager');                    
                    $mgremail = '';
                   if  ($manager !~ /NOT FOUND/){
                       $mgremail = (exists $managers{$manager}?$managers{$manager}:get_attribute("" , $manager , 'mail'));
                       $managers{$manager} = $mgremail unless exists $managers{$manager}; 
                       $manager =~ s/\\//;
                       ($manager) = $manager =~ /^CN=(.*?),\w+=/;
                   }                                       
               }else{
                   $manager = "SERVICE ACCOUNT";
               }
                                                   
               print (($accountstatus eq 'ACTIVE')?"$cname\t-\t$manager " . ($mgremail ne ''?"($mgremail)\n":"$mgremail\n"):"$cname\t-\t($accountstatus)\n" ); 
               $cname =~ s/,//;
               $manager =~ s/,//;
               print  GROUPMEMBERS (($accountstatus eq 'ACTIVE')?"$cname\,$manager " . ($mgremail ne ''?"($mgremail)\n":"$mgremail\n"):"$cname\, ($accountstatus)\n" );  
   
               ++$usercount;
           
           }elsif ($category eq 'CN=Computer,CN=Schema,CN=Configuration,DC=mycompany_changethis,DC=com'){
               print "$cname\t-\tCOMPUTER\n";
               print GROUPMEMBERS "$cname\t-\tCOMPUTER\n";
               ++$usercount;
               next;
        
           }else{
               print "UNABLE TO ACCESS INFORMATION FOR $cname\n";
               print GROUPMEMBERS "$cname\t-\tUNABLE TO ACCESS\n";
               ++$usercount;
               next;     
            }

}
  
   print GROUPMEMBERS "-------------------------------------------\n\n";
   print  "-------------------------------------------\n\n";
  
}

sub get_attribute{

    my $filter = shift @_;
    my $dn = shift @_;
    my $attribute = shift @_;
    my $memberurl = "<GC://$dn>";
    my $adocon = Win32::OLE->new("ADODB.Connection") or die "Cannot create connection.\n";
    $adocon->{Provider} = "ADsDSOObject";
    $adocon->Open();
    my $query=Win32::OLE->new("ADODB.Command") or die "Cannot create command object.\n";
    $query->{ActiveConnection}=$adocon;
    my $query_result = Win32::OLE->new("ADODB.RecordSet");

    if ($attribute eq 'member' && $subgroup == 0){
          $query->{CommandText} = "$ldap_url;$filter;$attribute;subtree"; 
    }elsif($attribute eq 'bangmgr'){     
          $query->{CommandText} = "$ldap_url;$filter;manager;subtree"; 
    }else{
          $query->{CommandText} = "$memberurl;$filter;$attribute;base";
    }
    
   $query_result=$query->Execute or return("NOT FOUND");

   my $value = $query_result->Fields(0)->{Value};
   my $recordcount = $query_result->{RecordCount};  

   if ($recordcount != 0){ 
       if ($attribute eq 'member'){    
            return (\@{$query_result->Fields(0)->{Value}});    
       }     
 
   if ($attribute eq 'cn'){
        return 'DISABLED';
   }

   if (defined $value){
       return $value;  
   }else{
       
       if ($attribute eq 'bangmgr'){           
            until ($query_result->{EOF}){            
                last if defined $query_result->Fields(0)->{Value};
                $query_result->MoveNext;
            }
            return ((defined $query_result->Fields(0)->{Value})?$query_result->Fields(0)->{Value}:"NOT FOUND");      
       }
       
       if ($attribute eq 'manager' && $dn !~ /svc/i){
                 (my $displayName) = $dn =~ /^CN=(.*?),\w+=/;
                 $displayName =~ s/CWR\.//;
                 $displayName =~ s/\./ /;
                 $displayName =~ s/^(!|_)//;
                 (my $firstname) = $displayName =~ /^(\w+)/;
                 my $surname = ($displayName =~ /(\w+)$/)?$1:"";  
                 $surname =~ s/^_// if defined $surname;
                 $firstname =~ s/^_// if defined $firstname;                      
                 my $mgrdn = get_attribute("(|(&(displayName=*$firstname*)(displayName=*$surname*))(&(sAMAccountName=*$firstname*)(sAMAccountName=*$surname*)))", "", 'bangmgr'); 
                 return $mgrdn;
                    
       }
       
       return ("NOT FOUND ") ;      
    }

    }else{
        return ('ACTIVE') if $attribute eq 'cn';
        return ("NOT FOUND");
    }
 
}  
