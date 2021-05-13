#!/usr/bin/python
"""DNS dinamico con TopHost.
Lancia thdns -h per informazioni sull'uso.
Daniele Paganelli @ 2007
Guido del Puente @ 2018 fix
Emanuele Magrin @ 2021 more fixes and code cleaning
CreativeCommons Attribution-ShareAlike"""
########################
# CONFIGURAZIONE
########################
# Nome utente e password per il pannello di controllo TopHost:
userid = "username"
passwd = "password"

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

version='0.3'
storedip=None
test=True
ip=''


help="""#################################
thdns %s - Gestione DNS per TopHost
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
""" 

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
import json
import httplib, urllib
from collections import OrderedDict

def getip():
	"""Ottieni l'ip da checkip.dyndns.org"""
	si='Address: '
	r=urlopen('http://checkip.dyndns.org').read()
	i=r.find(si)+len(si)
	e=r.find('<',i)
	return r[i:e]

def getsid():
	"""Connetti al cpanel per ottenere l'id di sessione"""
	# La procedura e' necessaria per ottenere i cookie,
	# che chiameremo PSI e SID
	# PSI corrisponde al PHPSESSID= , presente nella risposta di /x-login,
	# mentre SID corrisponde al cookie che viene rilasciato nel body della pagina /godns
	global sid,psi

	# Prepara l'header ed effettua una POST a cp.tophost.it/x-login,
	# fornisci le credenziali e ottieni PHPSESSID= dall'header,
	# che verra' inserito su "psi"
	headersauth = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
	auth = urllib.urlencode([('user',''+userid),('pass',''+passwd)])
	conn = HTTPSConnection('cp.tophost.it')
	conn.request('POST', '/x-login', auth, headersauth)
	r=conn.getresponse()
	psi=r.getheader('Set-Cookie').split(';')[0].replace('PHPSESSID=','')
	conn.close

	# Prepara l'header ed effettua una GET a /x-httpsstatus,
	# necessaria per determinare il cookie "nodo"
	# che si trovera' nell'header
	headers_httpstatus = {'Cookie': 'PHPSESSID='+psi+'; logged_cp='+userid}
	conn = HTTPSConnection('cp.tophost.it')
	conn.request('GET', '/x-httpsstatus', headers=headers_httpstatus)
	x_httpsstatus=conn.getresponse()
	node=x_httpsstatus.getheader('set-cookie').split(';')[0]
	conn.close()

	# Prepara l'header ed effettua una GET a /godns,
	# necessaria per determinare il cookie "sid"
	# che sara' presente nella pagina come dato hidden
	headers_godns = {'Cookie': 'PHPSESSID='+psi+'; logged_cp='+userid+'; '+node}
	conn = HTTPSConnection('cp.tophost.it')
	conn.request('GET', '/godns', headers=headers_godns)
	godns=conn.getresponse()
	page=godns.read()
	bound='<input type=hidden name=sid value='
	s=page.find(bound); e=page.find('>',s)
	sid=page[s+len(bound):e].replace('"','')
	conn.close()

	return sid,psi

def dnscp(act,params):

	"""Effettua l'azione richiesta sul pannello dns"""
	myheaders = {"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain", "Cookie":"seeweb="+psi,"Content-length":"%d" % len(params)}
	conn = HTTPSConnection("ns1.th.seeweb.it", timeout=100, context=ssl._create_unverified_context())
	conn.request("POST", act, params, myheaders)

	response = conn.getresponse()
	hdrs = response.getheaders()
	msg = response.msg
	reply = response.status
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

	# Quando l'aggiornamento riesce, viene proposto un redirect.
	# Non ci interessa, quindi consideriamolo riuscito.
	if msg!='OK' and reply!=302:
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
		print "L'IP corrente corrisponde gia' a quello memorizzato ("+storedip+")"
		noedit = 'Non modifico '
		for key in dyn:
			noedit=noedit+key+', '
		print (noedit[:-2])
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
