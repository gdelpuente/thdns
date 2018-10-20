#!/usr/bin/python
"""DNS dinamico con TopHost.
Lancia thdns -h per informazioni sull'uso.
http://www.mythsmith.it
Daniele Paganelli @ 2007
CreativeCommons Attribution-ShareAlike"""
########################
# CONFIGURAZIONE
########################
# Nome utente e password per il pannello di controllo TopHost:
userid = "userid"
passwd = "passwd"

# Nomi (domini di terzo livello) dei quali si desidera aggiornare l'ip: (devono gia' essere presenti come record di tipo A.)
dyn=['@','www']

# File dove memorizzare l'ip dell'ultimo aggiornamento:
logip='/tmp/thdns.ip'

# FINE CONFIGURAZIONE
#-------------------------

#######################
#######################
# COSTANTI
#######################

version='0.2'
storedip=None
test=True
ip=''


help="""#################################
thdns %s - Gestione DNS per TopHost
http://www.mythsmith.it
#################################

Utilizzo: thdns [<opzioni> <ip>]

ARGOMENTI:
	[<ip>]: Aggiorna i nomi all'ip dato in argomento (equivalente al flag -i <ip>, o --ip=<ip>).

OPZIONI:
	-f [<ip>], --forza[=<ip] : Forza l'aggiornamento (nota: non abusare di questa opzione per non sovraccaricare i server)

	-g [<ip>],--gentile[=<ip]: Controlla se l'aggiornamento e' necessario, paragonando l'ip attuale (in argomento o ottenuto dalla rete) all'ip dell'ultima chiamata al programma, memorizzato in %s. Questo e' il comportamento predefinito.

	-h, --help : stampa questo messaggio di aiuto
	-n <dom>, --nome=<dom>: Aggiorna questo/i sottodominio/i, ignorando quelli configurati. <dom> e' una lista di sottodomini separati da virgole.

Tutte le opzioni e gli argomenti sono facoltativi. Nel caso non venga specificato un ip ne' in argomento ne' tra le opzioni, verra' ottenuto in rete tramite il servizio checkip.dyndns.org (non funziona con i proxy).

Esempi:
	thdns -f 192.168.1.1 -> forza l'aggiornamento all'ip
	thdns 192.168.1.1 / thdns -g 192.168.1.1 -> se %s non corrisponde a 192.168.1.1, aggiorna
	thdns -> ottiene l'indirizzo dalla rete; se non corrisponde a %s, aggiorna (equivalente a thdns -g)
""" % (version,logip,logip,logip)

ua='User-Agent','thdns/%s (+http://daniele.modena1.it/code/thdns/view)' % version

#######################
# FUNZIONI
#######################

from httplib import HTTPSConnection,HTTPS
from urllib2 import urlopen
from urllib import urlencode
from base64 import encodestring
from string import strip
from sys import argv,exit
from os.path import exists
from getopt import getopt
import ssl
import logging

def getip():
	"""Ottieni l'ip da checkip.dyndns.org"""
	si='Address: '
	r=urlopen('http://checkip.dyndns.org').read()
	i=r.find(si)+len(si)
	e=r.find('<',i)
	return r[i:e]

def getsid():
	"""Connetti al cpanel per ottenere l'id di sessione"""
	# "Basic" authentication encodes userid:password in base64. Note
	# that base64.encodestring adds some extra newlines/carriage-returns
	# to the end of the result. string.strip is a simple way to remove
	# these characters.
	global sid,psi
	auth = 'Basic ' + strip(encodestring(userid + ':' + passwd))
	conn = HTTPSConnection('cp.tophost.it')
	conn.putrequest('GET', '/dnsjump.php')
	conn.putheader('Authorization', auth )
	conn.putheader(ua[0],ua[1])
	conn.endheaders()
	r=conn.getresponse()
	psi=r.getheader('Set-Cookie').replace('PHPSESSID=','').replace('; path=/','')
	page=r.read()
	bound='<input type="hidden" name="sid" value="'
	s=page.find(bound); e=page.find('">',s)
	sid=page[s+len(bound):e]
	# urlCP=page.find("<form action=\"")
	# logging.warning(urlCP)
	conn.close()
	return sid,psi

def dnscp(act,params):
	"""Effettua l'azione richiesta sul pannello dns"""
	# conn=HTTPSConnection('ns1.th.seeweb.it', timeout=100, context=ssl._create_unverified_context())
	# conn.putrequest('POST', act)
	# conn.putheader('Host', 'ns1.th.seeweb.it')
	# conn.putheader('Connection', 'keep-alive')
	# conn.putheader("Content-length", "%d" % len(params))
	# conn.putheader("Origin", "https://cp.tophost.it")
	# conn.putheader("Content-type", "application/x-www-form-urlencoded")
	# conn.putheader(ua[0],ua[1])
	# conn.putheader("Referer", "ttps://cp.tophost.it/dnsjump.php")
	# conn.putheader('Cookie', 'seeweb='+psi )
	#
	# conn.endheaders()
	# conn.send(params)
	headers = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain", "Cookie":"seeweb="+psi,"Content-length":"%d" % len(params)}
	conn = HTTPSConnection("ns1.th.seeweb.it", timeout=100, context=ssl._create_unverified_context())
	conn.request("POST", act, params, headers)

	response = conn.getresponse()
	hdrs = response.getheaders()
	msg = response.msg
	reply = response.status
	# logging.warning("params: "+ params)
	# logging.warning("act: "+ act)
	# logging.warning("psi: "+ psi)
	# logging.warning(reply)
	# reply, msg, hdrs = conn.getreply()
	page = response.read()
	conn.close()
	return reply,msg,hdrs,page

def dnsinfo(name):
	"""Controlla quale indirizzo ip era presente nel pannello dns di tophost.
	Questa funzione fa il parsing della pagina per individuare
	l'ip associato al nome richiesto."""
	b1='<input type="hidden" name="name" value="%s">' % name
	i=data.find(b1)+len(b1)
	b2='<input type="hidden" name="value" value="'
	i=data.find(b2,i)+len(b2)
	e=data.find('">',i)
	return data[i:e]

def update(name):
	"""Aggiorna il valore per il nome richiesto, se necessario"""
	global ip
	old=dnsinfo(name)	# L'ip del DNS
	if ip==old:
		# Esci dalla funzione se l'ip del DNS era corretto
		print '[%10s]\t mantengo %s' % (name,old)
		return False

	# Modifica il nome
	params = urlencode({'name':name,
		'old_value':old,
		'new_value':ip,
		'type':'A',
		'action':'Modifica'})
	reply,msg,hdrs,page=dnscp('/dnscp/index.php?page=edit_record',params)
	if msg!='OK':
		print 'Errore di connessione per %s: %s, %s.' % (name,str(reply),msg)
		return False
	print '[%10s]\t era %s, aggiorno a %s' % (name,old,ip)
	return True

#######################
# SCRIPT
#######################

# Lettura parametri
if len(argv)>1:
	opts, args=getopt(argv[1:],'fghin:',['forza','help','gentile','nome='])
	for o,a in opts:
		if o in ['-h','--help']:
			print help
			exit(0)
		if o in ['-f','--forza']:
			test=False
			ip=a
		if o in ['-g','--gentile']:
			test=True
			ip=a
		if o in ['-n','--nome']:
			dyn=a.replace(' ','').split(',')

	if len(args)==1:
		ip=args[0]

if ip=='':
	ip=getip()

if test==True:
	# Compara con l'ip memorizzato
	if exists(logip):
		storedip=open(logip,'r').read()
	if storedip==ip:
		exit(0)
	else:
		open(logip,'w').write(ip)
else:
	open(logip,'w').write(ip)

# Inizio la sessione con il cpanel:
getsid()
params = urlencode({'sid': sid, 'b1': 'Vai al pannello del DNS'})
data=dnscp('/dnscp/',params)[-1]

# Aggiorna tutti i nomi richiesti sul pannello dns:
for n in dyn:
	update(n)
