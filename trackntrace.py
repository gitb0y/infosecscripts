# -*- coding: utf-8 -*-
################################################  COPYRIGHT  AND  DISCLAMER   ###########################################################
#																	#
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



from bs4 import BeautifulSoup, SoupStrainer
import simplejson
import threading
import cookielib
import argparse
from datetime import datetime as dt, timedelta
import csv
import datetime
import getpass
import urllib2
import urllib
import socket
import zlib
import json
import time
import sys
import re
import os



parser = argparse.ArgumentParser(description='A program that uses Track and Trace feature of SymantecCloud Messagelabs to locate emails.',
        epilog='''EXAMPLE: Search MessageLabs for emails sent to some users with a certain subject over the last 5 days:
                                 "> python trackntrace.py -d 5 -S "Your Invoice is Ready" -r user1@yourdomain.com user2@yourdomain.com''')
parser.add_argument('-S', '--subject', nargs='+', default=[""], help='Specifies the email subject(s) to search for. Input file is accepted.')
parser.add_argument('-s', '--sender', nargs='+', default=[""], help='Retrieve all emails sent by this sender(s). Input file is accepted.')
parser.add_argument('-r', '--recipient', nargs='+', default=[""], help='Search all emails sent to this address(es). Input file is accepted.')
parser.add_argument('-l', '--lasthop', nargs='+', default=[""], help='Look for all emails that were sent by this IP address(es). Input file is accepted.')
parser.add_argument('-d', '--days', nargs='?', type=int, choices=xrange(1, 31), help='No. of days prior to search for.')
parser.add_argument('-H', '--hours', nargs='?', type=int, choices=xrange(1, 25), help='No. of hours prior to search for.')
parser.add_argument('-M', '--min-date', nargs='?', help='Find all emails sent starting from this date. Date format: Y-m-d_I:Mp. Example: 2017-07-25_02:43am')
parser.add_argument('-X', '--max-date', nargs='?', help='Find all emails sent up to this date. Date format: Y-m-d_I:Mp. Example: 2017-07-25_08:20am')

parser.add_argument('-o', '--output', nargs='?', const='trackandtrace_result.csv', default='trackandtrace_result.csv', help='Where to write output report. Defaults to trackandtrace_result.csv.')

args = parser.parse_args()

#maxdate = dt.today()
#print maxdate
#maxdate = dt.strptime(str(maxdate), "%Y-%m-%d %H:%M:%S.%f")
#maxformat = "%Y-%m-%d"
#maxdate = maxdate.strftime(maxformat)
#maxdate = maxdate + " 23:59:59"
#date format 28-Jul-17



searchduration = []




def striptime(date, dateformat):

    mydatetime = dt.strptime(date, dateformat)    
    mydate = mydatetime.strftime("%d-%b-%y")
    myhour = mydatetime.time().strftime('%I')
    mymin = mydatetime.time().strftime('%M')
    myampm = mydatetime.time().strftime('%p')
    return([mydate, myhour, mymin, myampm])


### MIN DATE > CURRENT DATE ERROR
if args.min_date and dt.strptime(args.min_date, "%Y-%m-%d_%I:%M%p") > dt.strptime(str(dt.today()), "%Y-%m-%d %H:%M:%S.%f") :
    print "\n\nERROR: --min-date (-M) cannot be later than the current date. Exiting..."
    raise(SystemExit)
   
if args.min_date and not args.max_date:
    searchduration = striptime(args.min_date, "%Y-%m-%d_%I:%M%p") + striptime(str(dt.today()), "%Y-%m-%d %H:%M:%S.%f")
elif args.min_date and args.max_date:
    searchduration = striptime(args.min_date, "%Y-%m-%d_%I:%M%p") + striptime(args.max_date, "%Y-%m-%d_%I:%M%p")
elif args.days and args.hours:
    searchduration = striptime(str(dt.today() - timedelta(days=args.days, hours=args.hours)), "%Y-%m-%d %H:%M:%S.%f") + striptime(str(dt.today()), "%Y-%m-%d %H:%M:%S.%f")
elif args.days:
    searchduration = striptime(str(dt.today() - timedelta(days=args.days)), "%Y-%m-%d %H:%M:%S.%f") + striptime(str(dt.today()), "%Y-%m-%d %H:%M:%S.%f")
elif args.hours:
    searchduration = striptime(str(dt.today() - timedelta(hours=args.hours)), "%Y-%m-%d %H:%M:%S.%f") + striptime(str(dt.today()), "%Y-%m-%d %H:%M:%S.%f")
else:
    print "\n\nERROR: Unable to find search duration. Must specify at least -M, -d, or -H. Exiting..."
    raise(SystemExit)
    

 


## CAPTURE SYMANTEC LABS AND DOMAIN CREDENTIALS
slusername = raw_input("SymantecLabs Username:")
slpassword = getpass.getpass(prompt='Symanteclabs Password:')



slcjar = cookielib.CookieJar()
previoussearch = None

reload(sys)
sys.setdefaultencoding("UTF8") #http://blog.abhijeetr.com/2013/10/encoding-and-python-unicodedecodeerror.html


emailscount = 0
f =  open( os.path.join(os.getcwd(), args.output), "wb")
outputwriter = csv.writer(f)
outputwriter.writerow(["Subject","Sender","Recipient","Delivery Status","Message Direction","Sending Server Hostname",
                       "Sending Server IP","Sending Server HELO","SMTP Start Date","SMTP Finish Date"
                       ])
                        
## HTTP HEADERS SHARED AMONG DIFFERENT REQUESTS
defaultheaders = [
                   ("Connection" , "Keep-Alive"),
                   ("Accept" , r"text/html, application/xhtml+xml, */*"),
                   ("User-Agent" , r"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"),
                   ("Accept-Encoding" , r"gzip, deflate"),
                   ("DNT" , 1),
                   ("Accept-Language" , r"en-PH"),
        ]


def logintolabs(slusername, slpassword):

   
    ## THIS CLASS IS NEEDED FOR PREVENTING URLLIB2 FROM AUTO REDIRECTING. WHEN IT AUTO-REDIRECTS,
    ## THE PAGE CONTAINING THE SAML REQUEST DISAPPEARS SO WE WONT BE ABLE TO PASS THESE AROUND WHEN AUTHENTICATING
    ## OR USING IT IN OUR REFERER LINK. SEE  http://stackoverflow.com/questions/554446/how-do-i-prevent-pythons-urllib2-from-following-a-redirect
    class DontRedirect(urllib2.HTTPErrorProcessor):
        def http_response(self, request, response):
            return response
        https_response = http_response
        
    ############################################################################
    ## GET THE LOGON PAGE
    getlogonrequrl = r'https://identity.symanteccloud.com/Logon'
    getlogonopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    getlogonopener.addheaders = [
        ("Host" , "identity.symanteccloud.com"),
        ("Upgrade-Insecure-Requests" , 1),
        ] + defaultheaders
    getlogonres = getlogonopener.open(getlogonrequrl)
    unzipgetlogonres = zlib.decompress(getlogonres.read(), 16+zlib.MAX_WBITS)
    rsidrex = re.search(r'(?<=rsid\=)\w+', unzipgetlogonres)
    rsid = rsidrex.group(0)
    if rsid is None:
        return("Unable to login. RSID error.")
 
    ############################################################################
    ## SUBMIT SYMANTEC CLOUD LOGON CREDENTIALS
    logonurl = r"https://identity.symanteccloud.com/Logon/logon?rsid=" + rsid
    logincreds = { r'Logon.Username' : slusername,
                  r'Logon.Password' : slpassword,
                  r'X-Requested-With' : r'XMLHttpRequest'
                }
    logondata = urllib.urlencode(logincreds)
    logonopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    logonopener.addheaders = [('Accept' , r'*/*'),
                        (r'Content-Type' , r'application/x-www-form-urlencoded; charset=UTF-8'),
                        (r'X-Requested-With' , 'XMLHttpRequest'),
                        ('Referer' , getlogonrequrl),
                        ('Host', r'identity.symanteccloud.com'),
                        (r'Cache-Control', r'no-cache'),
                        ] + defaultheaders
    print "\n\nLogging on to Symantec Cloud...",
    logonres = logonopener.open(logonurl, logondata)
    logonresrex = re.search(r'is incorrect', logonres.read())
    if logonresrex is not None:
        logonreserr = logonresrex.group(0)
        if logonreserr is not None:
            return("Incorrect username or password.")
   
    ############################################################################
    ### SUBMIT rsid
    clientslaburl = r'https://identity.symanteccloud.com/?rsid=' + rsid
    clientslabopener = urllib2.build_opener(DontRedirect,urllib2.HTTPCookieProcessor(slcjar))
    clientslabopener.addheaders = [
                        ('Referer' , getlogonrequrl),
                        ('Host', r'identity.symanteccloud.com'),
                        (r'Cache-Control', r'no-cache'),
                        ] + defaultheaders
    clientslabres = clientslabopener.open(clientslaburl)

    ############################################################################
    ### EXTRACT SAML RESPONSE
    clientsurl = r'https://clients.messagelabs.com/'
    clientsopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    clientsopener.addheaders = [
                        ('Host', r'clients.messagelabs.com'),
                        ] + defaultheaders
    clientsres = clientsopener.open(clientsurl)
    unzipclientsres=zlib.decompress(clientsres.read(), 16+zlib.MAX_WBITS)
    samlreqloc = clientsres.geturl()
    samlredresrex = re.search(r'(?<=SAMLResponse" value=")(.+?)"', unzipclientsres)
    try:
        samlredressid = samlredresrex.group(1)
    except:
        print "Invalid SymantecLabs credentials. Please try again..."
        raise(SystemExit)
    if samlredressid is None:
        return("Unable to login. SAML error.")
    
    ############################################################################
    ## SUBMIT OUR SAML RESPONSE TO GET OUR AUTHENTICATED COOKIE FOR USE WITH  CLIENTS.MESSAGELABS.COM
    samlposturl = r'https://clients.messagelabs.com/saml/post/ac'
    samlpostopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    samlpostopener.addheaders = [
                        (r'Content-Type' , r'application/x-www-form-urlencoded'),
                        ('Referer' , samlreqloc),
                        ('Host', r'clients.messagelabs.com'),
                        (r'Cache-Control', r'no-cache'),
                        ] + defaultheaders
    samlredressid = samlredressid.replace(r'&#43;', r'+')
    samlredressid = samlredressid.replace(r'&#61;', r'=')
    samlformdata = {'SAMLResponse' : samlredressid, 'RelayState' : ''}
    samlpostdata = urllib.urlencode(samlformdata)
    #print "Submitting SAML response token..."
    samlpostres = samlpostopener.open(samlposturl, samlpostdata)
    print "Success!!!\n"
    return("YES")
    

###############################################################################
###############################################################################

def submitsearch(searchparam, searchduration):

    for param in searchparam:
        if param != "":
            param = param.encode('utf-8').strip()


    global previoussearch

    
    ## LOAD THE EMAIL TRACK AND TRACE

    loadsearchurl = r'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx'
    loadsearchopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    loadsearchopener.addheaders = [
                        ('Content-Type' , r'text/html; charset=utf-8'),
                        ('Host', r'clients.messagelabs.com'),
                        ('Referer', 'https://clients.messagelabs.com/Dashboard/Dashboard.aspx'),
                        ] + defaultheaders
    loadsearchres = loadsearchopener.open(loadsearchurl)
    unziploadsearchres=zlib.decompress(loadsearchres.read(), 16+zlib.MAX_WBITS)
    soup = BeautifulSoup(unziploadsearchres, "html.parser")
    viewstate = soup.select("#__VIEWSTATE")[0]['value'].decode('utf-8')
    eventvalidation = soup.select("#__EVENTVALIDATION")[0]['value'].decode('utf-8')
    viewstategenerator = soup.select("#__VIEWSTATEGENERATOR")[0]['value'].decode('utf-8')
    timezone = soup.find(id="ctl00_ctl00_BodyContentPlaceholder_FirstContentPlaceholder_userControlSearch_labelSelectedTimeZone").string
    

    ############################################################################

    ## SUBMIT SEARCH REQUEST
    #print "Submitting search request for sender \"" + senderemailadd.encode('utf-8').strip() + "\" with subject \"" + phishsubject.encode('UTF-8').strip() + "\""
    searchposturl = r'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx '
    searchpostopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    searchpostopener.addheaders = [
                        (r'Content-Type' , r'application/x-www-form-urlencoded'),
                        ('Referer' , 'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx'),
                        ('Host', r'clients.messagelabs.com'),
                        ('Connection', 'Keep-alive'),
                        (r'Cache-Control', r'no-cache'),
                        ] + defaultheaders

    searchformdata = {
                        '__EVENTARGUMENT' : '',	
                        '__EVENTTARGET' : 'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$buttonSearch',
                        '__EVENTVALIDATION' : eventvalidation,
                        '__LASTFOCUS'	: '',
                        '__SCROLLPOSITIONX' :	0,
                        '__SCROLLPOSITIONY' :	341,
                        '__VIEWSTATE' : viewstate,
                        '__VIEWSTATEENCRYPTED' : '',
                        '__VIEWSTATEGENERATOR' : '04051C3B',	
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$tabCurrentlySelected' : 'Search',	
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlEmailResults$radioButtonResultsOptions' : 'radioButtonViewResults',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListAdvanceSearch' : 'AdvanceSearchDefault',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListAdvanceSearchEmailSize' : 'ANY',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListAdvanceSearchService' : 'ANY',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListDayPeriods' :	'1.00:00:00',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListHourPeriods' : '00:30:00',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$minute' : searchduration[2],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$hour' : searchduration[1],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$date' : searchduration[0],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$amPm' : searchduration[3],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$minute' : searchduration[6],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$hour' : searchduration[5],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$date' : searchduration[4],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$amPm' : searchduration[7],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListSubjectLine' : 'C',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$hiddenDateRangeDaysHoursOrSpecificSelected' : 'SpecificDateTime',	
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$searchTimeZone$DropDownListTimeZones' : 'GMT',
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$textboxFrom' : searchparam['sender'],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$textboxTo' : searchparam['recipient'],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$textboxSubjectLine' : searchparam['subject'],
                        'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$textboxAdvanceSearchSendingExternalIP' : searchparam['lasthop'],
                        'ctl00$ctl00$BodyContentPlaceholder$LocaleDropDownList' : 'en-US',


                      }
  
    searchpostdata = urllib.urlencode(searchformdata)
    searchpostres = searchpostopener.open(searchposturl, searchpostdata)
    unzipsearchpostres=zlib.decompress(searchpostres.read(), 16+zlib.MAX_WBITS)


#########################
### GET TNTSESSIONID


    loadtnturl = r'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx'
    loadtntopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    loadtntopener.addheaders = [
                        ('Content-Type' , r'text/html; charset=utf-8'),
                        ('Host', r'clients.messagelabs.com'),
                        ('Referer', 'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx'),
                        ] + defaultheaders
    loadtntres = loadtntopener.open(loadtnturl)
    unziploadtntres=zlib.decompress(loadtntres.read(), 16+zlib.MAX_WBITS)
    #REDIRECT PAGE HERE ="/Tools/Track-And-Trace/TrackAndTracePortlet.aspx (matato)
    csrfresrex = re.search('(?<=X-CSRF-Token\'\, \')(.+?)\'\)\;', unziploadtntres)


    tntsoup = BeautifulSoup(unziploadtntres, "html.parser")
    try:
        tntsessid = tntsoup.select("#ctl00_ctl00_BodyContentPlaceholder_FirstContentPlaceholder_tntSessionId")[0]['value']
    except:
        print unzipsearchpostres
        
    previoussearch = { "tntsessid" : tntsessid,
                       "viewstate" : viewstate,
                       "eventvalidation" : eventvalidation,
                       "viewstategenerator" : viewstategenerator,
                     }
                       
    tntcsrf = csrfresrex.group(1)
    searchstatus = getsearchstatus(tntsessid, tntcsrf)
    if searchstatus == "RESET":
        (matchcount, tntsessid, tntcsrf) = submitsearch(searchparam, searchduration)
        return(matchcount, tntsessid, tntcsrf)

    else:
        return searchstatus
        
def getsearchstatus(tntsessid, tntcsrf):
    ################################################################################
    ### Get status of the current search

    getstatusurl = r'https://clients.messagelabs.com/Tools/Track-And-Trace/services/TnTApi.asmx/RetrieveSearchStatus '
    getstatusopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    getstatusformdata = {"request" :{"SessionId" : tntsessid}}
    getstatusreq = urllib2.Request(getstatusurl, data=json.dumps(getstatusformdata),
                                    headers = {
                                                 r'Content-Type' : r'application/json; charset=utf-8',
                                                 r'Accept' : r'txt/plain, */*; q=0.01',
                                                 r'User-Agent': r"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                                                 r'X-CSRF-Token' : tntcsrf,
                                                 r'X-Requested-With' : 'XMLHttpRequest',
                                                 'Referer' : 'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx',
                                                 'Host' : r'clients.messagelabs.com',
                                                 'Accept-Encoding' : r'gzip, deflate',
                                                 r'Cache-Control' : r'no-cache',
                                                 'DNT' : 1,
                                                }
                                    )

    getstatuspostres = getstatusopener.open(getstatusreq)
    searchstatus = json.loads(getstatuspostres.read())['d']['Status']
    if searchstatus == 'Completed' or searchstatus == 'CompletedWithErrors':
        resetsearch()
        return "RESET"
    while searchstatus != 'Completed' and searchstatus != 'CompletedWithErrors':
         getstatuspostres = getstatusopener.open(getstatusreq)
         sys.stdout.write('.')
         getstatusresult = json.loads(getstatuspostres.read())
         searchstatus = getstatusresult['d']['Status']
         matchcount = getstatusresult['d']['NumberOfMatchingEmails']
         time.sleep(5)
          

    print "\nDone.\n"
    return (matchcount, tntsessid, tntcsrf)

#######################################################################################
#######################################################################################
### Retrieve search result

def getresult(matchcount, tntsessid, tntcsrf):
    allresults = []
    getresulturl = r' https://clients.messagelabs.com/Tools/Track-And-Trace/services/TnTApi.asmx/RetrieveSearchResult'
    getresultopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    startindex = 0;
    while matchcount > 0:
        getresultformdata = {"request":{"Length":100,"SessionId":tntsessid,"SortBy":"ReceivedDateUtc","SortDirection":"desc","StartIndex":startindex}}
        getresultreq = urllib2.Request(getresulturl, data=json.dumps(getresultformdata),
                                        headers = {
                                                     r'Content-Type' : r'application/json; charset=utf-8',
                                                     r'User-Agent': r"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                                                     r'Accept' : r'txt/plain, */*; q=0.01',
                                                     r'X-CSRF-Token' : tntcsrf,
                                                     r'X-Requested-With' : 'XMLHttpRequest',
                                                     'Referer' : 'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx',
                                                     'Host' : r'clients.messagelabs.com',
                                                     'Accept-Encoding' : r'gzip, deflate',
                                                     r'Cache-Control' : r'no-cache',
                                                     'DNT' : 1,
                                                    }
                                        )


        getresultpostres = getresultopener.open(getresultreq)
        searchresult = json.loads(getresultpostres.read())
        if searchresult['d']['TotalResultsCount'] == 0:
            print "Too many search results"
            raise(SystemExit)
        allresults.append(searchresult['d']['Results'])
        matchcount -= 100
        startindex += 100
        
    return(allresults)
 
######################################################################################
######################################################################################

def resetsearch():
    ## RESET FORM BEFORE SUBMITTING
    resetposturl = r'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx '
    resetpostopener = urllib2.build_opener(urllib2.HTTPCookieProcessor(slcjar))
    resetpostopener.addheaders = [
                        (r'Content-Type' , r'application/x-www-form-urlencoded'),
                        ('Referer' , 'https://clients.messagelabs.com/Tools/Track-And-Trace/TrackAndTracePortlet.aspx'),
                        ('Host', r'clients.messagelabs.com'),
                        (r'User-Agent', r"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"),
                        (r'Cache-Control', r'no-cache'),
                        ] + defaultheaders

    resetformdata = {'__EVENTTARGET' :  'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$buttonClearSearch',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$textboxTo' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$textboxFrom' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListDayPeriods' : '1.00:00:00',           
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$textboxSubjectLine' :	'',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$tabCurrentlySelected' : 'Search',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlEmailResults$radioButtonResultsOptions' : 'radioButtonViewResults',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$searchTimeZone$DropDownListTimeZones' : 'GMT',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$date' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$hour' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$minute' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerFrom$amPm' : "AM",
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$date' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$hour' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$minute' : '',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$DateTimePickerTo$amPm' : "AM",
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListAdvanceSearchService' : 'ANY',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListAdvanceSearchEmailSize' : 'ANY',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$dropDownListAdvanceSearch' : 'AdvanceSearchDefault',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$searchStatus' : 'SearchInProgress',
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$tntSessionId' : previoussearch['tntsessid'],
                      'ctl00$ctl00$BodyContentPlaceholder$FirstContentPlaceholder$userControlSearch$hiddenDateRangeDaysHoursOrSpecificSelected' : 'dropDownListDayPeriods',
                      'ctl00$ctl00$BodyContentPlaceholder$LocaleDropDownList' : 'en-US',
                      '__EVENTARGUMENT' : '',
                      '__LASTFOCUS' : '',
                      '__VIEWSTATEGENERATOR' : previoussearch['viewstategenerator'],
                      '__VIEWSTATE' : previoussearch['viewstate'],
                      '__EVENTVALIDATION' : previoussearch['eventvalidation'],
                      '__SCROLLPOSITIONX' : '0',
                      '__SCROLLPOSITIONY' : '0',
                      '__VIEWSTATEENCRYPTED' : '',
                     
                      }
    resetpostdata = urllib.urlencode(resetformdata)
    resetpostres = resetpostopener.open(resetposturl, resetpostdata)
  

#################################################################################################################
def searchemails(subject, sender, recipient, lasthop, searchduration ):

    searchparam = {}
    searchparam['subject'] = subject
    searchparam['sender'] = sender
    searchparam['recipient'] = recipient
    searchparam['lasthop'] = lasthop
    daterange = str(searchduration[0]) + "_" + str(searchduration[1]) + ":" + str(searchduration[2]) + str(searchduration[3]) + " to " + str(searchduration[4]) + "_" + str(searchduration[5]) + ":" + str(searchduration[6]) + str(searchduration[7])
    global emailscount
    global querycount
    
    print "\nSearching all emails from  " + daterange + "..."
    print "Search Parameters: "
    print "  Subject: " + subject
    print "  Sender: " + sender
    print "  Recipient: " + recipient
    print "  Sending IP: " + lasthop
    
    if isloggedin == "YES":
        if previoussearch is not None: # Means a previous search was done. We need to reset the form before running a new search.
            resetsearch()
        
        matchcount, tntsessid, tntcsrf = submitsearch(searchparam, searchduration)
        active_accounts = 0

        if matchcount < 1:
            modified_subject = '_'.join(subject.split())
            print "       No result found. Retrying with subject " + "\"" + modified_subject + "\"..."
            searchparam['subject'] = modified_subject
            matchcount, tntsessid, tntcsrf = submitsearch(searchparam, searchduration)

        if matchcount > 0:
            timessent = str(matchcount)
            emailscount = emailscount + matchcount
            print "Found " + timessent + " emails from " + daterange
            allresults = getresult(matchcount, tntsessid, tntcsrf)

            outputentry = []

            if len(allresults) == 0:
                print "WE GOT TOO MANY SEARCH RESULT. YOU MAY WANT TO BREAK DOWN RECIPIENTS OR SENDERS INTO INDIVIDUAL ADDRESSES"
                raise(SystemExit)




            
            for result in allresults:                         
               for entry in result:
                    delivery_status = str(entry['Delivery']['DeliveryStatus'])
                    if delivery_status == '05NotAvailable':
                        delivery_status = 'Not delivered'
                    elif delivery_status == '04Success':
                        delivery_status = 'Success'
                    subject = entry['Subject']
                    sender = entry['Sender']
                    if subject is None:
                        subject = "No Subject"
                    if sender is  None:
                        sender = "No Sender"
                    direction = entry['Direction']
                    if direction == "I": direction = "Inbound"
                    if direction == "O": direction = "Outbound"
                        
                        
                    outputwriter.writerow([subject,sender,entry['Recipient'],delivery_status,
                                           direction,entry['SendingServerHostName'],entry['SendingServerIP'],entry['HeloString'],entry['ReceivedDateUtc'],
                                           entry['SmtpFinishedDateUtc']
                                           ])                   
                    
            
                                    

        else:
             timessent = 0
             uniquerecipients = 0
             print "Found no other recipient for the past " + str(searchduration) + " day(s).\n"
             
    else:
        print "\nUnable to login to SymantecCloud. " + isloggedin



def combine_list(arglist):
    itemlist = []
    for item in arglist:
        if os.path.isfile(os.path.join(os.getcwd(), item)):
            sublist = [entry.strip() for entry in open(os.path.join(os.getcwd(), item), 'r', 0)]
            itemlist = itemlist + sublist
        else:
            itemlist.append(item)
                
    return(itemlist)


#################################################################################################################



### LOGIN TO MESSAGELABS

isloggedin = logintolabs(slusername, slpassword)



### PROCESS INPUTS

subjectlist = combine_list(args.subject)
senderlist = combine_list(args.sender)
recipientlist = combine_list(args.recipient)
lasthoplist = combine_list(args.lasthop)

querycount = 0

for subject in subjectlist:
    for sender in senderlist:
        for recipient in recipientlist:
            for lasthop in lasthoplist:
                searchemails(subject, sender, recipient, lasthop, searchduration)
                querycount +=1



print "\nOutput written to: \".\\" + args.output + "\""
print "Total Search Made: " + str(querycount)
print "Total Emails Found: " + str(emailscount)
print "\n\n"




