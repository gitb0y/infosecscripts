#!/usr/bin/perl
#
#################################################################################
#                                                                               #
# Description: A program that sends out notification emails to managers of      #
# terminated employees.                                                         #                                               
# Usage: #perl leavernotifier.pl                                                #
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
use Cwd;
use Win32::OLE qw(in with);
use Win32::OLE::Const 'Microsoft Outlook';
use Win32::OLE::Variant;
use Spreadsheet::ParseExcel;

our $editbeforesend = 'ON';
our $senderemail = 'myemail@mycompany.com_changethis';
my $rootdse=Win32::OLE->GetObject("LDAP://RootDSE") or die "CONNECTION TO SERVER FAILED. EXITING...", "\n\n";
my $basedn=$rootdse->Get("RootDomainNamingContext");
my $ldap_url="<GC://$basedn".">";
our $subgroup = 0;
my $sourcefolder = getcwd;
my $termsheet = `dir /B "$sourcefolder" |findstr TERM`;
my $cwrsheet = `dir /B "$sourcefolder" |findstr CWR`;
chomp ($termsheet, $cwrsheet);
my $cwrusers;
my %managers;
my %mgremails;
my %termusers;
    
print "\nPROCESSING $termsheet\n\n\n\n";
print "Legend:\n\n\n";
print "(/) - Disabled\t(X) - Deleted\t(C) - Converted\n-----------------------------------------------\n\n\n\n\n";

### (1) READ THE CWR-TO-EMP LIST AND STORE IN A HASH VARIABLE FOR EASY LOOKUPS

if (defined $cwrsheet){
        $cwrusers = create_hashcwr($cwrsheet);
     }        
      my $parser   = Spreadsheet::ParseExcel->new();
      my $workbook = $parser->parse($termsheet);
      die $parser->error(), ".\n" if ( !defined $workbook );
      my $senderdn = get_attribute("(&(mail=" . $senderemail .")(objectClass=user))", "", "distinguishedName");
      my $sendername = get_attribute("(&(mail=" . $senderemail .")(objectClass=user))", $senderdn, "givenName");
      my $sendersn = get_attribute("(&(mail=" . $senderemail .")(objectClass=user))", $senderdn, "sn");
      $sendername = $sendername . " $sendersn";


### (2) OPEN AND READ THE TERM LIST LINE BY LINE.  ROWS 11 AND 12 HOLD THE MANAGER AND HIS EMAIL ADDRESS. THIS MUST BE CHANGED IF THE EXCEL SHEET COLUMNS ARE CHANGED.
         
      for my $worksheet ( $workbook->worksheets() ) {
          my ( $row_min, $row_max ) = $worksheet->row_range();
          for my $row ( 2  .. $row_max ) {
              my $name = $worksheet->get_cell( $row, 3);
              next if (exists $termusers{($name->value())});
              $termusers{($name->value())} = '';
              my $mgr = $worksheet->get_cell($row, 11);
              my $manager = $mgr->value();
              my $mgrmail = $worksheet->get_cell($row, 12);
              my $manageremail = $mgrmail->value();
              my $displayname = $name->value();
              $mgremails{$manager} = $manageremail;
              
### (3) SKIP USERS WHO WERE FOUND IN THE CWR-TO-EMP LIST
                         
              if (defined $cwrusers && exists ${$cwrusers}{($name->value())}){
                 printf "%-28s%s", "$displayname", "- (C)\n";
                 next;
           }
              my $managerdn = get_attribute("(&(mail=" . $manageremail .")(objectClass=user))", "", "distinguishedName");
              if (ref $managerdn){
                 print "MULTIPLE MANAGERS FOUND. Exiting...\n";
                 print $_, "\n" foreach @{$managerdn};               
                 exit;
                
              }
 
### (4) FORMAT AND SPLIT NAME SO WE CAN USE IT AS OUR SEARCH FILTER 
             
              $displayname =~ s/\'//g;                            
               my @string = split(/\s|-/, $displayname);
               my $firstname = $string[0];
               my $lastname = $string[-1];
               my $fltr = '';
               my $filter = '';
               foreach (@string){
                   next if $_ eq '';
                   $fltr = "(displayName=*" . $_ . "*)";
                   $filter .= $fltr;
                }
 
 
### (5) CREATE THE LDAP/AD SEARCH FILTER FOR distinguishedName ATTRIBUTE LOOKUP. WE NEED TO SEARCH FIRST THE dn BEFORE WE CAN SEARCH FOR THE ACCOUNT STATUS LATER.
           
               $filter = "(|(&" . $filter . "(objectClass=user)" . ")(&(givenName=*$firstname*)(sn=*$lastname*)(objectClass=user))(&(cn=*$firstname*)(cn=*$lastname*)(objectClass=user))" . ")";

                $| = 1;
                printf "%-28s", "$displayname";
                my $dn = get_attribute($filter, "", "distinguishedName");
                my @dn;    
                #print "DN IS $dn\n";
### (5.1) SOME USERS HAVE MULTIPLE ACCOUNTS. WE ARE ONLY AFTER ACCOUNTS WHICH HAVE NOT BEEN NLE'd YET (moved to OU=NLE). WE MAKE SURE THAT ALL THE USER'S ACCOUNTS ARE IDENTIFIED.               
        
               if (ref $dn){                 
                   #print "MULTIPLE DN\n";                  
                   foreach (@{$dn}){
                       #print "DN $_\n";
                       if ($_ =~ /NLE/ || $_ =~ /Disabled/){  
                         if ($_ eq ${$dn}[-1]){
                            print "- (/)\n";
                            
                         }                     
                        next;
                     }            
                     #print "We are pushing DN Here\n";  
                       
                       push @dn, $_;
                    }                                    
                }else{
 
### (5.2) IF AN ACCOUNT IS NOT FOUND (DELETED), THE SEARCH RETURNS "NOT FOUND", WE MARK IT WITH (X). IF IT HAS BEEN DISABLED OR NLE'd ALREADY (moved to OU=NLE), WE MARK IT WITH (/). 
                  
                    if ($dn =~ /NOT/){
                      print "- (X)\n";
                      next; 
                      
                    }
                    if ($dn =~ /NLE/ || $dn =~ /Disabled/){                       
                       print "- (/)\n";
                       next;
                       
                    }
                    #print "We are pushing DN here\n";
                    push @dn, $dn;
                }
 
 
### (6) ONCE WE'VE GATHERED ALL THE USER'S ACCOUNTS, WE GET THE ACCOUNT STATUS OF EACH. ENABLED ACCOUNTS ARE MARKED (ACTIVE).
                  my $dnindex = 0;
                  my $dncount = scalar @dn;
                                           
                  foreach my $dn(@dn){
                     unless ($dn =~ /NOT/ || $dn=~ /NLE/ || $dn=~ /Disabled/)  {
                        my $accountstatus = get_attribute("(userAccountControl:1.2.840.113556.1.4.803:=2)", $dn, 'cn' );
                        if ($accountstatus eq 'ACTIVE'){                                                    
                           if ($dn eq $dn[-1]){
                             print ($dncount > 1?"- (ACTIVE)($dncount)":"- (ACTIVE)", "\n");
                           }                           
                             $dn =~ s/(^CN=.*),DC=int,DC=mycompany_changethis,DC=com/$1/;  
                           
                           
### (6.1) THEN WE COLLECT ALL USER ACCOUNTS REPORTING TO THE SAME MANAGER SO THAT WE ONLY HAVE TO SEND ONE EMAIL NOTIFICATION TO A PARTICULAR MANAGER.
              
                           push @{$managers{$manager}}, "<b>$displayname</b>" . " (<i>$dn</i>)";
                        }           
                     }
                  }
                       
          }
                       
 
 

### (7) ONCE WE ARE DONE READING AND PARSING THE ENTIRE TERM SHEET, WE WILL COMPOSE OUR EMAIL NOTIFICATION HERE.
   my $count = 0;    
   print "\n\n\n\n\n\n<<< Still Active Accounts >>>\n\n\n" unless scalar keys %managers == 0;                 
   foreach my $managername (keys %managers){                             
       my $message = '';
       #print "\nMANAGER: $managername ($mgremails{$managername})\n" if $auditor eq 'ON';
       
       foreach (@{$managers{$managername}}){ 
          (my $directreport) = $_;
           $directreport =~ s/(\<b\>|\<\/b\>|\<i\>|\<\/i\>)//g;                                 
           print "(" . ++$count . ") " . "$directreport\n";
           $message .= "<tr><td>$_</td></tr>";
       }
       print "\n";   
       my $header = '<p style="font-family:Calibri;font-size:10pt;margin-top: 0px;"><i>This message will be sent to ' . "$mgremails{$managername}</i></p>";
                        $message = ($editbeforesend eq 'ON'?$header:"") . '<p style="font-family:Calibri;font-size:11pt;margin-top: 0px;"><b>' . $managername . ',</b></p> <p style="font-family:Calibri;font-size:11pt;">The Security team has performed a review of no longer employed personnel and we are showing the following user' . (scalar @{$managers{$managername}} > 1?"s":"") . ' reporting to you as no longer employed according to our PeopleSoft system.   </p> <p style="font-family:Calibri;font-size:11pt;"><table style="font-family:Calibri;font-size:10pt;" border=1 cellspacing=0 cellpadding=1>' . $message . '</table></p> <p style="font-family:Calibri;font-size:11pt;">The former staff member' . (scalar @{$managers{$managername}} > 1?"s":'') . ' above still appear' . (scalar @{$managers{$managername}} > 1?"":'s') . ' to have an active domain account.  We need you to please complete an NLE ticket using MyIT as soon as possible so that we can perform the necessary account deactivation steps.</p>
<p style="font-family:Calibri;font-size:11pt;">Additionally, once you have completed this ticket, please reply to us and provide us with the ticket number for tracking purposes. However, if the employee NLE status is incorrect please reply to us with an explanation so that we have a statement for our records. </p>
<i><p style="font-family:Calibri;font-size:11pt;margin-bottom: 0px">Kind Regards,</p></i>
<p style="font-family:Calibri;font-size:11pt;margin-bottom: 0px; margin-top: 0px;">' . $sendername . '</p>
<b><p style="font-family:Calibri;font-size:11pt;margin-bottom: 0px; margin-top: 0px;">IT Security</p>
</b>';              


### (7.1) FINALLY, WE START SENDING THE EMAILS. WHEN $editbeforesend IS SET TO ON, THE EMAIL WILL BE SENT TO $senderemail. THIS IS USEFUL WHEN WE WANT TO REVIEW THE USER ACCOUNTs BEFORE SENDING. THIS IS THE DEFAULT BEHAVIOR.
 
       sendemail(($editbeforesend eq 'ON'?$senderemail:"$mgremails{$managername}" . ';itsecurity@mycompany_changethis.com'), $message, $managername);
                                                               
     }
}  
       
  print "\n\n\n\n\n"; 

sub create_hashcwr{
 
 
my %cwrusers;  
my $cwrsheet = shift @_;
my $parser   = Spreadsheet::ParseExcel->new();
my $workbook = $parser->parse($cwrsheet);
die $parser->error(), ".\n" if ( !defined $workbook );    


    for my $worksheet ( $workbook->worksheets() ) {
       my ( $row_min, $row_max ) = $worksheet->row_range();
       for my $row ( 2  .. $row_max ) {
         my $lastname = $worksheet->get_cell( $row, 1);
         my $firstname = $worksheet->get_cell($row, 2); 
         my $name = join(" ", $firstname->value(), $lastname->value());
         $cwrusers{$name} = '';
       }
     }
   return \%cwrusers;
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


   if ($attribute eq 'member' && $subgroup == 0 or $attribute eq 'distinguishedName'){
      $query->{CommandText} = "$ldap_url;$filter;$attribute;subtree"; 
   }elsif ($attribute eq 'bangmgr'){     
           $query->{CommandText} = "$ldap_url;$filter;manager;subtree";          
   }else{
      $query->{CommandText} = "$memberurl;$filter;$attribute;base";
   }
    
   #print "\nEXECUTING QUERY $query->{CommandText}, $attribute\n\n\n";
   $query_result=$query->Execute or return("NOT FOUND");
   my $recordcount = $query_result->{RecordCount};  
   my $value = $query_result->Fields(0)->{Value};
   #print "RECORDCOUNT IS $recordcount\n";

   if ($recordcount != 0){ 
      if ($attribute eq 'member'){    
           return (\@{$query_result->Fields(0)->{Value}});    
      }     
 
      if ($attribute eq 'cn'){
         return 'DISABLED';
      }

      if (defined $value){
          if ($recordcount == 1) {
             return $value;
          }else{
             my @values;  
             until ($query_result->EOF){          
                $value = $query_result->Fields(0)->{value};
                push @values, $value; 
                $query_result->MoveNext;
             }
         
           return \@values;
          }      
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
       print "WE ARE RETURNING HERE\n";
       return ("NOT FOUND ") ;      
    }

   }else{
        return ('ACTIVE') if $attribute eq 'cn';    
        return ("NOT FOUND");
   }
}  


sub sendemail {

   my $address = shift @_;
   my $message = shift @_;
   #my $date = shift @_;
   #$date = " (Term. Report Date: $date)";
   my $manager = shift @_;
   my $Outlook = new Win32::OLE('Outlook.Application');
   my $item = $Outlook->CreateItem(0);         
   $item->{'Subject'} = "NLE Ticket Needed - $manager";
   $item->{'To'} = $address;
   $item->{'HTMLBody'} = $message;
   $item->{'From'} = $senderemail;
   $item->Send();
                         
}
