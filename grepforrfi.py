#!/usr/bin/python2.5
#Simple script for parsing web logs for RFIs and Webshells v1.2
#By Irongeek
import re
import cgi
import urllib2
import socket
import sys
import string
import datetime
import zipfile
import os
socket.setdefaulttimeout(5)

#Main setting below
fni1 = "/home/irongeek/logs/irongeek.com/http/access.log"
fni2 = "/home/irongeek/logs/irongeek.com/http/access.log.0"
fno = "/home/irongeek/irongeek.com/uniquerfis.txt"
deadfn = "/home/irongeek/irongeek.com/deadrfis.txt"
fpagename = "/home/irongeek/irongeek.com/webshells-and-rfis.htm"
#Make sure the path below exists.
wscapdir ="/home/irongeek/irongeek.com/wscap/" 
wscapdirweb="/wscap/"
debugon=False

if "-d" in sys.argv:
	debugon=True
#Grep function based on http://casa.colorado.edu/~ginsbura/pygrep.htm
def grep(string,list):
    expr = re.compile(string, re.IGNORECASE)
    return filter(expr.search,list)
	
#Based on http://stackoverflow.com/questions/12953253/searching-for-substring-in-element-in-a-list-an-deleting-the-element-python
def rgrep(string,list):
	flist = [l for l in list if string not in l]
	return flist

#Help from http://www.seehuhn.de/blog/52
parts = [
    r'(?P<host>\S+)',                   # host %h
    r'\S+',                             # indent %l (unused)
    r'(?P<user>\S+)',                   # user %u
    r'\[(?P<time>.+)\]',                # time %t
    r'"(?P<request>.+)"',               # request "%r"
    r'(?P<status>[0-9]+)',              # status %>s
    r'(?P<size>\S+)',                   # size %b (careful, can be '-')
    r'"(?P<referer>.*)"',               # referer "%{Referer}i"
    r'"(?P<agent>.*)"',                 # user agent "%{User-agent}i"
]
pattern = re.compile(r'\s+'.join(parts)+r'\s*\Z')

def getlink(line):
	#if debugon: print line
	try:
		m = pattern.match(line)
		fields = m.groupdict()
		temp=fields['request'].split("http://")
		link = temp[len(temp)-1]
		link = "http://"+link.strip(' HTTP/1.1').strip(' HTTP/1.0')
		return link
	except:
		return "BadLink"

#Based on http://blog.client9.com/2007/11/fast-datetime-parsing-in-python.html
month_map = {'Jan': 1, 'Feb': 2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6, 'Jul':7, 
    'Aug':8,  'Sep': 9, 'Oct':10, 'Nov': 11, 'Dec': 12}
def apachetime(s):
    global month_hash
    return datetime.datetime(int(s[7:11]), month_map[s[3:6]], int(s[0:2]), \
         int(s[12:14]), int(s[15:17]), int(s[18:20]))		
		
#Based on http://computer-programming-forum.com/56-python/948ba5b17703c016.htm
def compare (line1,line2):
    # Nicely sucks out the apache date stamp
    datestamp1 = apachetime(line1[string.find(line1,"[") + 1:string.rfind(line1,"]")])
    datestamp2 = apachetime(line2[string.find(line2,"[") + 1:string.rfind(line2,"]")])
    # Compare the date stamps and return appropriate value
    if datestamp1 < datestamp2:
            return -1
    elif datestamp2 < datestamp1:
            return 1
    else:
            return 0 

#Based on http://code.activestate.com/recipes/502263/
def unique(inlist, keepstr=True):
  typ = type(inlist)
  if not typ == list:
    inlist = list(inlist)
  i = 0
  tempinlist=[]
  tempinlist.extend(inlist)
  for index, line in enumerate(tempinlist):
	line = re.sub(r'\[(?P<time>.+)\]',"[00/Jan/0000:00:00:0 -0000]",line)
	line = re.sub(r'"(?P<request>.+)"',"GET /i.php/page="+getlink(line)+" HTTP/1.1",line)
	tempinlist[index] = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',"0.0.0.0",line)

  while i < len(tempinlist):
    try:
		valtokill=tempinlist.index(tempinlist[i], i + 1)
		#print "dup"
		#print tempinlist[valtokill]
		#print inlist[valtokill]
		del tempinlist[valtokill]
		del inlist[valtokill]
		
    except:
      i += 1
  if not typ in (str, unicode):
    inlist = typ(inlist)
  else:
    if keepstr:
      inlist = ''.join(inlist)
  return inlist

def maketable(inlist):
	fpage.write('<table align="center" border="1" width="75%"><tr>')
	fpage.write('<td align="center"><font color="#ff0000"><b>Attacker</b></font></td>')
	fpage.write('<td align="center"><font color="#000000"><b>Whois IP</b></font></td>')
	fpage.write('<td align="center"><font color="#009900"><b>Request<br><font size="1">(Truncated if over 60 chr for display, link should still work)</font></b></font></td>')
	fpage.write('<td align="center"><font color="#009900"><b>View on PHP Decoder</b></font></td>')
	fpage.write('<td align="center"><font color="#0000ff"><b>Agent</b></font></td>')
	fpage.write('<td align="center"><font color="#999900"><b>Referer</b></font></td>')
	fpage.write('<td align="center"><font color="#aa00aa"><b>Time</b></font></td>')
	fpage.write('<td align="center"><font color="#aa00aa"><b>Backup</b></font></td>')
	fpage.write('</tr>')
	for line in reversed(inlist):
		#print "test"+line+"test"
		m = pattern.match(line)
		fields = m.groupdict()
		link=getlink(line)
		fpage.write('<tr>')
		fpage.write('<td><font color="#ff0000">'+cgi.escape(fields['host'])+'</font></td>')
		fpage.write('<td><font color="#000000"><a href="http://www.robtex.com/ip/'+cgi.escape(fields['host'])+'.html#whois">Whois</a></font></td>')
		fpage.write('<td><font color="#009900"><a rel="nofollow" href="http://nullrefer.com/?'+link+'">'+link[:60]+'</a></font></td>')
		fpage.write("<td><a href=\"javascript:void(0)\" onclick='document.forms[\"phpdecode\"].url.value = \""+link+"\";document.phpdecode.submit();'>View on PHP Decoder</a></td>") 
		fpage.write('<td><font color="#0000ff">'+cgi.escape(fields['agent'])+'</font></td>')
		fpage.write('<td><font color="#0000ff">'+cgi.escape(fields['referer'])+'</font></td>')
		fpage.write('<td><font color="#aa00aa">'+cgi.escape(fields['time'])+'</font></td>')
		wsname=link.replace("http://","").replace("/","_").replace(":","_").replace(".","_").replace("?","").replace("<","_").replace(">","_").replace("=","_")+".zip"	
		wspathandfile=wscapdir+wsname
		if os.path.isfile(wspathandfile):
			fpage.write('<td><font color="#aa00aa"><a href="'+wscapdirweb+wsname+'">Archived Webshell</a></font></td>')
		else:
			fpage.write('<td><font color="#aa00aa">Not In Archive</font></td>')
			
		fpage.write('</tr>')
	fpage.write("</table>")


def SaveWSToZip(link,wscode):
	wsname=link.replace("http://","").replace("/","_").replace(":","_").replace(".","_").replace("?","").replace("<","_").replace(">","_").replace("=","_")+".zip"	
	wspathandfile=wscapdir+wsname
	if os.path.isfile(wspathandfile):
			if debugon: print "File already exists! Skipping." + wspathandfile
			#Do nothing
	else:
		if debugon: print "File does not exist! Let's create it. " + wspathandfile
		wsfile = zipfile.ZipFile(wspathandfile, "w")
		wsfile.writestr(wsname+".txt",wscode)
		wsfile.close()	

#SaveWSToZip("test","test")

		# Based on https://gist.github.com/884204 and http://stackoverflow.com/questions/802134/changing-user-agent-on-urllib2-urlopen
def url_exists(line):
	link=getlink(line)
	headers = { 'User-Agent' : 'Hello, I\'m not attacking your site, but someone else tried using this file on your server as an RFI against my site. Contact Irongeek at Irongeek.com for more details http://www.irongeek.com/i.php?page=webshells-and-rfis' }
	request = urllib2.Request(link, None, headers)
	#request.get_method = lambda : 'HEAD'
	if debugon: print link
	try:
		response = urllib2.urlopen(request)
		if debugon: print response.info()
		if int(response.headers["Content-Length"]) < 1000000:
			wscode=response.read()
			#if debugon: print wscode
			SaveWSToZip(link,wscode)
		if debugon: print "True"
		response.close()
		return True
	except:
		#if debugon: print e.code 
		#if debugon: print e.msg
		if debugon: print "False"
		return False

#Begin MAIN code
fin1 = open(fni1, 'r')
fin2 = open(fni2, 'r')

#Open as read, read it, then close
fout = open(fno, 'r')
foldc = fout.readlines()
fout.close()
deadf = open(deadfn, 'r')
deadmatches=deadf.readlines()
deadf.close() 
fc = fin2.readlines()+fin1.readlines()
matches = grep('=http(s?):\/\/',fc)
matches = unique(foldc+matches)
matches = grep('\.txt|\.inc|\.dat|\.bak',matches)

matches = rgrep(' "http',matches)
matches = rgrep('.jpg?',matches)
matches.sort(compare) 

tmatches=[]

for line in matches:
	if url_exists(line):
		tmatches.append(line)
	else:
		deadmatches.append(line)


fpage = open(fpagename, 'w+')	
#fmatches = grep('^(?:(?!Mozilla\/4.0 \(compatible; MSIE 6\.0; Windows NT 5\.1; \.NET CLR 1\.1\.4322; \.NET CLR 2\.0\.50727\)).)*$\r?\n?',matches)
fpage.write("<title>Web Shells and RFIs Collection</title>")
fpage.write("<h1><center><b>Web Shells and RFIs Collection</b></center></h1><p>")
fpage.write('<form name="phpdecode" method="post" action="https://defense.ballastsecurity.net/decoding/index.php">') 
fpage.write("<input type='hidden' name='url' value=''>")
fpage.write("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;I wrote a little script to periodically look through my web logs for unique RFIs and Web Shells, "
			"and then collect them on one page where I can go look at them or download them to add to my Web Shell library. Many of these attacks "
			"are repeated multiple time, so I ignore the time fields in judging if an RFI/Web Shell is unique. I've coded it to weed out links to "
			"Web Shells that 404. I also use nofollow and a referrer hiding service so it does not look like I'm attacking anyone with the web "
			"shells (but the check for 404 sort of looks suspicious). This page will also let you link off to "
			"<a href=\"http://firebwall.com/\">firebwall.com</a> where you can use their PHP decoder to look at the obfuscated code. Enjoy my Web "
			"Shell zoo, it should update itself every hour or so. If you see your domain on the list of websites hosting Web Shells you are likely "
			"pwned and should clean up your server."
			"<p><center><a href=\"http://irongeek.com/downloads/grepforrfi.txt\">Source code that generates this page</a></center><p>")
fpage.write("<p><center><b>Filtered For More Likely Live Webshell RFIs</b></center><p>")
maketable(matches)
fpage.write("<p><center><b>Likely Dead Links</b></center><p>\n\r")
maketable(deadmatches)
fpage.write("</form><p>")

#Open for write, doing this last so it is less likely to blank the file if script is killed
fout = open(fno, 'w')
matches=tmatches
for line in matches:
        #print line 
        fout.write(line)

deadf = open(deadfn, 'w')
deadmatches = unique(deadmatches)
for line in deadmatches:
        #print line
        deadf.write(line)
