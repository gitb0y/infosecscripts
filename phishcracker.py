################################################  COPYRIGHT  AND  DISCLAMER   ###########################################################
#																	#
# A program that parses .msg files to extract various information such as smtp headers, embedded links and attachments.                 #
# Author: Mark alvarez                                                                                                                  #
# Usage: See -h for details.                                                                                                            #
#                                                                                                                                       #
#  Copyright (c) 2016, Mark Jayson Alvarez												#
#  All rights reserved.															#
#																	#
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following 		#
#  conditions are met:															#
#																	#
#    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.	#
#    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer	#
#      in the documentation and/or other materials provided with the distribution.							#
#																	#
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 	#
#    BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT	#
#    SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL	#
#    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS	#
#    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT  			#
#    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 	#
#    SUCH DAMAGE.															#
#																	#
#########################################################################################################################################

from dns import resolver
from shutil import copy
import hashlib
import win32com.client
import dns.resolver
import simplejson
import pywintypes
import threading
import pythoncom
import ipaddress
import argparse
import datetime
import urllib2
import urllib
import socket
import zlib
import json
import time
import sys
import ssl
import re
import os



#########################



startTime = time.time()
parser = argparse.ArgumentParser(description='A program that parses .msg files and displays various information such as smtp hops w/ rbl blacklist status, embedded links w/url reputation, etc.',
        epilog='EXAMPLE: Parse all emails in "Mailbox - Mark Alvarez -> Phish" folder. "python phishcracker.py -m "Mailbox - Mark Alvarez" -i Phish"')
parser.add_argument('-m', '--mailbox', nargs='?', const='', default='',
                    help='Mailbox containing emails to read.')
parser.add_argument('-c', '--cachedir', nargs='?', const=os.path.join(os.getcwd(), "phishcracker_attachments"), default=os.path.join(os.getcwd(), "phishcracker_attachments"),
                    help='Temporary folder to save msg attachments to. Defaults to "phishcracker_attachments" folder in the current directory.')
parser.add_argument('-i', '--input', nargs='?', const='', default='',
                    help='.msg file, directory, or folder inside the Inbox containing emails with .msg attachments. Use ":" to specify complete path (e.g., "SOC:Phish Submissions:Unprocessed":')
parser.add_argument('-b', '--blacklist-status', help='Determines the RBL blacklist status of each SMTP hop from various DNS servers. Does not do a lookup by default.', action='store_true')
parser.add_argument('-n', '--rbl-servers', nargs='*', help='Additional name servers (DNS) to query for RBL blacklist status.')
parser.add_argument('-w', '--web-url-reputation', help='Does a lookup VirusTotal to determine the web URL reputation of each embedded link.', action='store_true')
parser.add_argument('-l', '--location-search', help='Searches http://ipinfo.io to determine the country location of an SMTP hop. Searching is disabled by default.', action='store_true')
parser.add_argument('-v', '--verbose', help='Display verbose output in the screen.', action='store_true')
parser.add_argument('-f', '--flagged', help='Skip non-flagged messages.', action='store_true')
args = parser.parse_args()


ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


### IF INPUT IS NOT AN MSG FILE OR A FOLDER, LAUNCH OUTLOOK APP
if args.input[-4:] != '.msg' and not os.path.isdir(args.input):
    try:
        ns = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
    except:
        print "\nUnable to launch Outlook app??? Exiting..."
        raise(SystemExit)

    try:
        inbox = ns.Folders(args.mailbox).Folders("Inbox")
    except:
        if args.mailbox == "":
            print "\nForgot to specify mailbox? Use \"-m\".  Exiting..."
        else:
            print "\n" + args.mailbox + " does not exist??? Exiting..."
        raise(SystemExit)


##############  SET OUTPUT FOLDERS ##############


if not os.path.exists(args.cachedir) or not os.path.isdir(args.cachedir):
    try:
        if args.verbose: print ">>> Creating a temporary directory in " + args.cachedir
        os.makedirs(args.cachedir)
    except:
        print "Unable to create a temporary storage for msg attachments. Check permissions."
        sys.exit(0)

stagingdir = args.cachedir
outputdir = os.path.join(os.getcwd(), "phishcracker_output")

if not os.path.exists(outputdir) or not os.path.isdir(outputdir):
    try:
        if args.verbose: print ">>> Creating an output directory in " + outputdir
        os.makedirs(outputdir)
    except:
        print "Unable to create an output directory for phishcracker. Check permissions."
        sys.exit(0)



linksfilename =   "phishcracker_embeddedlinks_" + str(time.time()) + ".txt"
embedded_links = open(os.path.join(outputdir, linksfilename), "w", 0)
blacklistfilename = "phishcracker_blacklisted_IPs_" + str(time.time()) + ".txt"
blacklisted_senders = open(os.path.join(outputdir, blacklistfilename), "w", 0)

reload(sys)
sys.setdefaultencoding("UTF8") 


#################################################################################################################

class Resolver(threading.Thread):  
    def __init__(self, address, rblserver, result_dict):
        threading.Thread.__init__(self)
        self.rblserver = rblserver
        self.address = address + rblserver
        self.result_dict = result_dict

    def run(self):
        try:
            answers_txt = resolver.query(self.address, "TXT")[0].to_text()
            self.result_dict[self.rblserver] = answers_txt
        except resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            pass
        except dns.resolver.YXDOMAIN:
            pass
        
def get_rblhosts(ip): 
    rblservers = ["0spam.fusionzero.com","access.atlbl.net","access.redhawk.org","all.rbl.webiron.net","all.s5h.net","any.dnsl.ipquery.org","aspews.ext.sorbs.net","b.barracudacentral.org","babl.rbl.webiron.net","bad.psky.me",
                    "badconf.rhsbl.sorbs.net","bhnc.njabl.org","bl.blocklist.de","bl.deadbeef.com","bl.emailbasura.org","bl.spamcannibal.org","bl.spamcop.net","bl.technovision.dk","blackholes.five-ten-sg.com","blackholes.mail-abuse.org",
                    "blacklist.hostkarma.com","blacklist.sci.kun.nl","blacklist.woody.ch","block.dnsbl.sorbs.net","bogons.cymru.com","cabl.rbl.webiron.net","cbl.abuseat.org","cdl.anti-spam.org.cn","combined.abuse.ch","combined.rbl.msrbl.net",
                    "crawler.rbl.webiron.net","db.wpbl.info","dnsbl.cobion.com","dnsbl.cyberlogic.net","dnsbl.dronebl.org","dnsbl.inps.de","dnsbl.kempt.net","dnsbl.njabl.org","dnsbl.proxybl.org",
                    "dnsbl.sorbs.net","dnsbl-1.uceprotect.net","dnsbl-2.uceprotect.net","dnsbl-3.uceprotect.net","dnsrbl.org","drone.abuse.ch","duinv.aupads.org","dul.dnsbl.sorbs.net","dul.ru",
                    "dyna.spamrats.com","dynip.rothen.com","escalations.dnsbl.sorbs.net","hbl.atlbl.net","hil.habeas.com","hostkarma.junkemailfilter.com","http.dnsbl.sorbs.net","http.dnsbl.sorbs.netimages.rbl.msrbl.net","images.rbl.msrbl.net",
                    "intercept.datapacket.net","ips.backscatterer.org","ix.dnsbl.manitu.net","korea.services.net","mail-abuse.blacklist.jippg.org","misc.dnsbl.sorbs.net","new.spam.dnsbl.sorbs.net","nomail.rhsbl.sorbs.net","no-more-funn.moensted.dk",
                    "noptr.spamrats.com","noservers.dnsbl.sorbs.net","ohps.dnsbl.net.au","old.spam.dnsbl.sorbs.net","omrs.dnsbl.net.au","orvedb.aupads.org","osps.dnsbl.net.au","osrs.dnsbl.net.au","owfs.dnsbl.net.au","owps.dnsbl.net.au",
                    "phishing.rbl.msrbl.net","probes.dnsbl.net.au","probes.dnsbl.net.auproxy.bl.gweep.ca","proxy.bl.gweep.ca","proxy.block.transip.nl","psbl.surriel.com","rbl.atlbl.net","rbl.interserver.net",
                    "rbl.iprange.net","rbl.megarbl.net","rbl.orbitrbl.com","rbl.schulte.org","rdts.dnsbl.net.au","recent.spam.dnsbl.sorbs.net","relays.bl.gweep.ca","relays.bl.kundenserver.de","relays.nether.net","residential.block.transip.nl",
                    "rhsbl.sorbs.net","ricn.dnsbl.net.au","rmst.dnsbl.net.au","safe.dnsbl.sorbs.net","short.rbl.jp","smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net",
                    "spam.abuse.ch","spam.dnsbl.sorbs.net","spam.rbl.msrbl.net","spam.spamrats.com","spamguard.leadmon.net","spamlist.or.kr","spamrbl.imp.ch","spamsources.fabel.dk","spamtrap.drbl.drand.net","srnblack.surgate.net",
                    "stabl.rbl.webiron.net","t3direct.dnsbl.net.au","tor.dnsbl.sectoor.de","torserver.tor.dnsbl.sectoor.de","truncate.gbudb.net","ubl.lashback.com","ubl.unsubscore.com","virbl.bit.nl","virbl.dnsbl.bit.nl",
                    "virus.rbl.jp","virus.rbl.msrbl.net","web.dnsbl.sorbs.net","wormrbl.imp.ch","zen.spamhaus.org","zombie.dnsbl.sorbs.net","combined.njabl.org"
                  ] 
    if args.rbl_servers: rblservers += args.rbl_servers
    results = {}
    threads = []

    for rblserver in rblservers:
        query = '.'.join(reversed(str(ip).split("."))) + "."
        resolver_thread = Resolver(query, rblserver, results)
        threads.append(resolver_thread)
        resolver_thread.start()

    for thread in threads:
        thread.join()

    return(results)

################################################################################################################

def parse_email(fullfilename, reporter):
    
    if args.verbose: print ">>> Parsing smtp headers and body..."
    session = win32com.client.Dispatch("Redemption.RDOSession") 
    mapiutils = win32com.client.Dispatch("Redemption.MAPIUtils") 
    safemailatt = win32com.client.Dispatch("Redemption.SafeMailItem")
    session.Logon
    
    try:
        mailattachment = session.GetMessageFromMsgFile(fullfilename)
    except:
        print "\n" + fullfilename + " does not exist? Exiting..."
        sys.exit(0)

    phishattachments = mailattachment.Attachments
    
    ### EXTRACT THE SMTP HEADER  
    mapiinetheader = mapiutils.HrGetOneProp(mailattachment.MAPIOBJECT, 0x007D001E)

    phishsubject = mailattachment.Subject
    if phishsubject == "": phishsubject = 'empty_subject'
    if reporter != "msg_file":
        print "       ",
    else:
        print "\n\n"
    phishrecipients = mailattachment.Recipients
    for recipient in phishrecipients:
	if(recipient.Fields(0x39FE001E)):
	        print "\n\nSent to: ",
		print recipient.Fields(0x39FE001E).encode('utf-8').strip()
	else:
		print "\n\nSent to: " + recipient.Address
    print "Subject: \"" + phishsubject.encode('UTF8') + "\""
    if reporter != "msg_file": print "       ",
    print "Date Sent: " + str(mailattachment.SentOn)
    
    

    ### EXTRACT THE SENDER EMAIL ADDRESS. RESOLVE X.400/500 ADDRESSES
    if mailattachment.SenderEmailAddress == "":
          sender = "<nothing found>"
          if reporter != "msg_file": print "       ",
          print "Sent By: " + sender
    else:
        if mailattachment.SenderEmailType == "EX":
            safemailatt.Item = mailattachment
            safemailattsender = safemailatt.Sender
            try:
               senderemailadd = safemailattsender.Fields(0x39FE001E).encode('utf-8').strip()
            except:
                senderemailadd = "<nothing found>"
            sender = senderemailadd
            if reporter != "msg_file": print "       ",
            print "Sent By: " + sender + "(" + mailattachment.SenderEmailAddress + ")" 
        else:
            senderemailadd = mailattachment.SenderEmailAddress.encode('utf-8').strip()
            sender = senderemailadd
            if reporter != "msg_file": print "       ",
            print "Sent By: " + sender

    if mapiinetheader is None:
        print "\n\n\nALERT!!! UNABLE TO EXTRACT THE HEADERS. SKIPPING...\n\n\n"
        return


    ### EXTRACT THE X-ENV-SENDER
    x_env_sender = re.search(r'(?<=X-Env-Sender: )(.+?@.+?)\n\w', mapiinetheader, re.DOTALL | re.IGNORECASE)
    if x_env_sender is None:
        x_env_sender = "<nothing found>"
    else:
        x_env_sender = x_env_sender.group(1).encode('utf-8').strip()
        x_env_sender = re.sub('\s+', '', x_env_sender)
        senderemailadd = x_env_sender
    if reporter != "msg_file": print "       ",
    print "X-Env-Sender: " + x_env_sender


    ### EXTRACT THE REPLY-TO
    newmapiinetheader = re.sub("In-Reply-To", "notreplyto", mapiinetheader)
    reply_to = re.search(r'(?<=Reply-To: )\b.+@.+\b', newmapiinetheader, re.IGNORECASE)
    if reply_to is None:
        reply_to = "<nothing found>"
    else:
        reply_to = reply_to.group(0).encode('utf-8').strip()
    if reporter != "msg_file": print "       ",
    print "Reply-To: " + reply_to

    ### EXTRACT THE RETURN-PATH

    return_path = re.search(r'(?<=Return-Path: ).+@.+', mapiinetheader, re.IGNORECASE)

    if return_path is None:
        return_path = "<nothing found>"
    else:
        return_path = return_path.group(0).encode('utf-8').strip()
        return_path = re.sub('<|>', '', return_path)
    if reporter != "msg_file": print "       ",
    print "Return-Path: " + return_path
 
    ### EXTRACT THE X-ORIGINATING-IP

    x_originating_ip = re.search(r'(?<=X-Originating-IP: ).+?(\d+\.\d+\.\d+\.\d+)', mapiinetheader, re.IGNORECASE)

    if x_originating_ip is None:
        x_originating_ip = "<nothing found>"
        if reporter != "msg_file": print "       ",
        print "X-Originating-IP: " + x_originating_ip
        
    else:
        x_originating_ip = x_originating_ip.group(1)
        if args.location_search:
            if reporter != "msg_file": print "       ",
            print "X-Originating-IP: " + x_originating_ip + " - " + urllib2.urlopen(r'http://ipinfo.io/' + x_originating_ip + '/country', context=ctx).read().strip()
        else:
            if reporter != "msg_file": print "       ",
            print "X-Originating-IP: " + x_originating_ip


    ### EXTRACT THE SMTP HOPS
    if args.verbose: print ">>> Extracting SMTP hops from the headers..."
    smtp_hops = re.findall(r'(?<=Received: from )(\d+\.\d+\.\d+\.\d+|.+?)\s+?by', mapiinetheader, re.DOTALL)
    hopcount = 0
    rblcount = 0
    if args.location_search:
        if reporter != "msg_file": print "       ",
        print "Hops:  (IP - Location)"
    else:
        if reporter != "msg_file": print "       ",
        print "Hops:  (IP)"


    if args.blacklist_status:
        if reporter != "msg_file": print "            ",
        print "     - RBL Blacklist Server:"

    for hop in reversed(smtp_hops):
        hop = re.sub('\r\n', '', hop)
        ip_re = re.search(r'(\d+\.\d+\.\d+\.\d+)', hop)
        if ip_re is not None:
            ip = ip_re.group(0)
            hostname = hop.split()[0]
            
        else:
            try:
                ip = socket.gethostbyname(hop)
            except socket.error:
                ip = "none"
            hostname = hop
        hopcount += 1


        if ip != "none":
            if args.location_search: ### DETERMINE IP LOCATION
                if ipaddress.IPv4Address(unicode(ip)).is_private == False:
                    country = urllib2.urlopen(r'http://ipinfo.io/' + ip + '/country', context=ctx).read().strip()
                    if reporter != "msg_file": print "            ",
                    print " " + str(hopcount) + ". " + hostname + "(" + ip + " - " + country + ")"
                else:
                    if reporter != "msg_file": print "            ",
                    country = 'anywhere/private_ip'
                    print " " + str(hopcount) + ". " + hostname + "(" + ip + " - " + country + ")"

            else:
                if reporter != "msg_file": print "            ",
                print " " + str(hopcount) + ". " + hostname + "(" + ip +  ")"

            if ipaddress.ip_address(unicode(ip)).is_private == False:           
                if args.blacklist_status:
                    if args.verbose: print ">>> Getting RBL blacklist status for " + ip + "..."
                    rblhosts = get_rblhosts(ip)
                    for rblhost,txtresult in rblhosts.iteritems():
                            if reporter != "msg_file": print "            ",
                            print '     - %s: (%s)' %(rblhost,txtresult)
                            
        else:
            country = "unknown"
            if reporter != "msg_file": print "            ",
            print " " + str(hopcount) + ". " + hostname + "(" + ip + " - " + country + ")"
            

  

    ### 13. EXTRACT ALL URLs IN THE BODY (https://mail.python.org/pipermail/tutor/2002-February/012481.html)
    if args.verbose: print ">>> Extracting embedded URLs from the email body..."
    phishbody = mailattachment.Body
    urls = '(%s)' % '|'.join("""http https ftp""".split())
    ltrs = r'\w'
    gunk = r'/#~:.?+=&%@!\-'
    punc = r'.:?\-'
    any = "%(ltrs)s%(gunk)s%(punc)s" % { 'ltrs' : ltrs,
                                         'gunk' : gunk,
                                         'punc' : punc }
    url = r"""
        \b                            # start at word boundary
        (                             # begin \1 {
            %(urls)s    :             # need resource and a colon
            [%(any)s] +?              # followed by one or more
                                      #  of any valid character, but
                                      #  be conservative and take only
                                      #  what you need to....
        )                             # end   \1 }
        (?=                           # look-ahead non-consumptive assertion
                [%(punc)s]*           # either 0 or more punctuation
                [^%(any)s]            #  followed by a non-url char
            |                         # or else
                $                     #  then end of the string
        )
        """ % {'urls' : urls,
               'any' : any,
               'punc' : punc }
    url_re = re.compile(url, re.VERBOSE)
    match = url_re.findall(phishbody)
    extracted_URLs = {}
    for item in match:
        extracted_URLs[item[0]] = None
    if args.verbose: print ">>> Found " + str(len(extracted_URLs)) + " embedded link(s)..."
    if len(extracted_URLs) > 0:
        if args.web_url_reputation:
            if reporter != "msg_file": print "      ",
            print "\nEmbedded links: (VirusTotal Scan Report) (see full URLs: \\phishcracker_output\\" + linksfilename + "\")"
            embedded_links.writelines("URL~URL Flagged as Malicious (VirusTotal)\n")
            if args.verbose: print ">>> Getting Virus total URL/site reputation..."
        else:
            if reporter != "msg_file": print "      ",
            print "\nEmbedded links: (see full URLs: \\phishcracker_output\\" + linksfilename + "\")"
            
    for url in extracted_URLs:

        cleanvendors = []
        unratedvendors = []
        othervendors = []
        maliciousvendors = []

        if args.verbose: print "Checking reputation for URL: " + url
        url = url.strip()



        if args.web_url_reputation:
            vt_reportresult = vtreport_url(url, "")
            time.sleep(15)
            rescode = vt_reportresult.get('response_code')
            scan_id = vt_reportresult.get('scan_id')
            verbose_msg = vt_reportresult.get('verbose_msg')
            while "come back later" in verbose_msg:
                vt_reportresult = vtreport_url(url, vt_reportresult.get('scan_id'))
                verbose_msg = vt_reportresult.get('verbose_msg')
                time.sleep(15)



            for vendor in vt_reportresult['scans']:
                if vt_reportresult['scans'][vendor]['result'] == 'clean site':
                    cleanvendors.append(vendor)
                elif vt_reportresult['scans'][vendor]['result'] == 'unrated site':
                    unratedvendors.append(vendor)
                elif vt_reportresult['scans'][vendor]['result'] == 'malicious site':
                    maliciousvendors.append(vendor)
                else:
                    othervendors.append(vendor)
            if reporter != "msg_file": print "            ",
            print " " + url[0:70] +  ' <' + ' malicious:' + str(len(maliciousvendors)) + ' | ' + ','.join(maliciousvendors) +  '>'
            embedded_links.writelines(url + "~" + ' <' + ' malicious:' + str(len(maliciousvendors)) + ' | ' + ','.join(maliciousvendors) + '>' + "\n")

        else:
            if reporter != "msg_file": print "            ",
            print " " + url[0:70]
            embedded_links.writelines(url + "\n")
    
    phish_attachments = mailattachment.Attachments
    att = [attachment for attachment in phish_attachments]

    for attachment in att:
        attfullfilename = os.path.join(stagingdir, attachment.FileName)
        if args.verbose: print ">>> Saving attachment into " + attfullfilename.encode('UTF8') + "..."
        if not os.path.isfile(attfullfilename):
            try:
                attachment.SaveAsFile(attfullfilename)
            except pywintypes.com_error:
                attachment.SaveAsFile(attfullfilename)
                


#################################################################################################################


#################################################################################################################
def vtreport_url(url, scan_id):
    reporturl = 'https://www.virustotal.com/vtapi/v2/url/report'
    reportparam = {"resource": url, "scan_id": scan_id, "scan": 1, "apikey": "e29eab716d49ee438ceb5d71e6064c4875ac7de378e646328afbd540e3e2fed1"}
    reportdata = urllib.urlencode(reportparam)
    reportreq = urllib2.Request(reporturl, reportdata)
    reportres = urllib2.urlopen(reportreq)
    jsonreportres = reportres.read()
    reportres_dict = json.loads(jsonreportres)
    return reportres_dict


#################################################################################################################





if args.input[-4:] == '.msg': ## if -i or --input argument ends in .msg, parse the .msg email as it is
    print "\n\nParsing \"" + args.input + "\"...",
    parse_email(args.input, "msg_file")
    
elif os.path.isdir(args.input): #DIRECTORY CONTAINING MSG FILES
    msgfiles =  ([os.path.abspath(os.path.join(root, file)) for root, dirs, files in os.walk(args.input) for file in files if file.endswith('.msg')])
    for msg in msgfiles:
        print "\n\nParsing \"" + str(msg) + "\"...",
        parse_email(msg, "msg_file")  

## 1. OPEN EACH EMAIL AND CHECK FOR ATTACHMENTS. SKIP IF THERE IS NOT AT LEAST ONE .MSG ATTACHMENT

else:
    try:
        phishfolder = inbox
        for folder in args.input.split(":"):
            phishfolder = phishfolder.Folders(folder)

    except Exception as e:
        print "\n" + args.mailbox + ' -> ' + args.input + " folder does not exist here? Exiting..."
        print e
        sys.exit(0)
    if args.verbose: print ">>> Processsing emails in " + args.mailbox + " -> " + args.input + "..."

    for message in phishfolder.items:
        if args.flagged:
            if message.FlagRequest == "":
                continue

        fullname = str(ns.CurrentUser)
        firstname = fullname.split()[0]
        attachments = message.Attachments
        phishmsgs = [attachment for attachment in attachments if attachment.Type == 5]
        if len(message.subject) == 0:
            reportsubject = "<empty>"
        else:
            reportsubject = message.Subject
        print "\nSubject: " + "\"" + reportsubject.encode('utf8').strip() + "\""

        reportedon = str(message.SentOn)

        
    ### 2. DETERMINE THE EMPLOYEE WHO REPORTED THE PHISH. RESOLVE SENDER ADDRESS TO INTERNET MAIL ADDRESS IF IT IS IN EXCHANGE (x400/500) FORMAT
        if message.SenderEmailType == "EX":
            safemail = win32com.client.Dispatch("Redemption.SafeMailItem")
            safemail.Item = message
            safemailsender = safemail.Sender
            reporter = safemailsender.Fields(0x39FE001E)
            if not reporter:
                reporter = "<nothing found>"

            print "Forwarded By: " + reporter + " on " + reportedon #http://www.outlookcode.com/d/code/getsenderaddy.htm#redemption
        else:
            reporter = message.SenderEmailAddress
            print "Forwarded By: " + reporter + " on " + reportedon

    ### IF THERE IS NO MSG ATTACHMENT, MOVE TO THE NEXT

        if len(phishmsgs) <= 0:
                continue
        else:
            print "\nAttachments:"
        

    ### 3. EXTRACT THE ATTACHMENTS ONE BY ONE SKIPPING THOSE THAT ARE NOT OF TYPE .MSG.
        attcount = 0
        for attachment in phishmsgs:
            simfound = 0
            attcount += 1
            print "\n   " + str(attcount) + ".)" + "\"" + attachment.FileName.encode('utf-8') + "\""
            print "    Extracting attachment..."
            
    ### 4. CONFIGURE THE PRE-REQUISITES SO THAT REDEMPTION WILL WORK
            reportername = reporter.replace('@', '')
            filename =   str(datetime.datetime.strptime(reportedon, '%m/%d/%y %H:%M:%S').strftime('%Y%m%d')) + "_" + str(attcount) + "_" + reportername + "_" + attachment.FileName #http://stackoverflow.com/questions/2265357/parse-date-string-and-change-format
            fullfilename = os.path.join(stagingdir, filename)

    ### 5. SAVE ATTACHMENT TO A TEMPORARY STAGING DIRECTORY SO WE CAN READ IT LATER
            if args.verbose: print ">>> Saving attachment into " + fullfilename.encode('UTF8') + "..."
            if not os.path.isfile(fullfilename):
                try:
                    attachment.SaveAsFile(fullfilename)
                except pywintypes.com_error:
                    filename =   str(datetime.datetime.strptime(reportedon, '%m/%d/%y %H:%M:%S').strftime('%Y%m%d')) + "_" + str(attcount) + "_" + reportername + "_" + hashlib.md5(attachment.FileName.encode('utf-8')).hexdigest() + ".msg" #http://stackoverflow.com/questions/2265357/parse-date-string-and-change-format
                    fullfilename = os.path.join(stagingdir, filename)
                    attachment.SaveAsFile(fullfilename)

            else:
                if args.verbose: print filename.encode('UTF8') + " already exists. Saving skipped..."


            parse_email(fullfilename, reporter)
            

try:
    ns.Logoff
except:
    pass


if args.input[-4:] != '.msg':
    print "\n\nDone processing all emails in " + args.mailbox + " -> " + args.input
else:
    print "\n\nDone processing \"" + args.input + "\"."
    
print ('Elapsed Time: {0} seconds.'.format(time.time() - startTime))
print "\n\n"








