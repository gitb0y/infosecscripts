#!/usr/bin/perl
# 
# Author: Mark Alvarez
#################################################################################
#                                                                               #
# Description: A program that finds outlook emails based on search pattern and  #
# moves them to specified folder(s).                                            #
#                                                                               #
# Usage: #perl outlookfinder.pl                                                   #
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
use Win32::OLE qw(in with);
use Win32::OLE::Const 'Microsoft Outlook';
use Win32::OLE::Variant;
use utf8;



my $outlook = Win32::OLE->GetActiveObject('Outlook.Application') || Win32::OLE->new('Outlook.Application', 'Quit');
my $ns = $outlook->GetNameSpace("MAPI");
my $sourcefolder = $ns->{'Folders'}{'Outlook_Main_Folder_changethis'};
$sourcefolder = $sourcefolder->Folders("Inbox");
my $destfolder = $sourcefolder->Folders("mark");



my ($counter1, $counter2, $counter3, $counter4, $counter5);
$counter1 = $counter2 = $counter3 = $counter4 = $counter5 = 0;


foreach my $msg (reverse in ($sourcefolder->{Items})){
    my $subject = $msg->{Subject};
    my $body = $msg->{Body};
    my $sender = $msg->{SenderName};
    my $senderemail = $msg->{SenderEmailAddress};
    my $date = $msg->{SentOn};
    my $creationtime = $msg->{CreationTime};
    my $cc = $msg->{CC};
    my $to = $msg->{To};
    my $recipients = $msg->{Recipients};


if ((defined $sender && $sender =~ /Lynar/i) or (defined $senderemail && $senderemail =~ /Lynar/i) or (defined $cc && $cc =~ /Lynar/i) or (defined $to && $to =~ /Lynar/i)){
	 say "Date: $creationtime"; 
        say "From: $sender" if defined $sender;
        say "FromEmail: $senderemail" if defined $senderemail;
        say "TO: $to" if defined $to;
        say "CC: $cc" if defined $cc  && $cc ne '';
        ++$counter1;
        $msg->{Categories} = "Red Category";
        $msg->{FlagRequest} = "Followup Flag";
        $msg->Move($destfolder->Folders("Lynar"));
        say "Moved to folder \"Lynar\"\n";

}

if ((defined $sender && $sender =~ /Zhang, Joy/i) or (defined $senderemail && $senderemail =~ /Zhang, Joy/i) or (defined $cc && $cc =~ /Zhang, Joy/i) or (defined $to && $to =~ /Zhang, Joy/i)){
        say "Date: $creationtime"; 
        say "From: $sender" if defined $sender;
        say "FromEmail: $senderemail" if defined $senderemail;
        say "TO: $to" if defined $to;
        say "CC: $cc" if defined $cc && $cc ne '';
        $msg->Move($destfolder->Folders("Zhang"));
        say "Moved to folder \"Zhang\"\n";

        ++$counter2;
}


if ((defined $sender && $sender =~ /zhaohuanhuan/i) or (defined $senderemail && $senderemail =~ /zhaohuanhuan\@mydomain.com_changethis/i) or (defined $cc && $cc =~ /zhaohuanhuan\@mydomain.com_changethis/i) or (defined $to && $to =~ /zhaohuanhuan\@mydomain.com_changethis/i)){
	say "Date: $creationtime"; 
        say "From: $sender" if defined $sender;
        say "FromEmail: $senderemail" if defined $senderemail;
        say "TO: $to" if defined $to;
        say "CC: $cc" if defined $cc  && $cc ne '';
        $msg->Move($destfolder->Folders("Zhaohuanhuan"));
        say "Moved to folder \"Zhaohuanhuan\"\n";

        ++$counter3;
}

if ((defined $subject && $subject =~ /派遣|无固定期限|合同|外服|part time|unfixed|contract|裁员|project Y|奖金|税|bonus|tax|年假|annual|leave|兼职|搬家|租约|终止|解除|termination|terminate|dismiss|补偿金|fixed|租赁|房东/i) or (defined $body && $body =~ /派遣|无固定期限|合同|外服|part time|unfixed|contract|裁员|project Y|奖金|税|bonus|tax|年假|annual|leave|兼职|搬家|租约|终止|解除|termination|terminate|dismiss|补偿金|fixed|租赁|房东/i)){
        say "Date: $creationtime"; 
        say "From: $sender" if defined $sender;
        say "FromEmail: $senderemail" if defined $senderemail;
        say "TO: $to" if defined $to;
        say "CC: $cc" if defined $cc  && $cc ne '';
        $msg->Move($destfolder->Folders("misc"));
        say "Moved to folder \"misc\"\n";
        ++$counter4;
}




}


say "Emails found containing \"Lynar\" in To:, From:, and CC: = $counter1";
say "Emails found containing \"Zhang, Joy\" in To:, From:, and CC: = $counter2";
say "Emails found containing 3rd keywords in To:, From:, and CC: = $counter3";
say "Emails found containing 4th keywords in Subject:, and Body: = $counter4";
