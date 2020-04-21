#!/usr/bin/python

import subprocess,re,sys,os
from datetime import datetime
from time import strftime
from scapy.all import *
import socket 
import argparse


def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-sP", help="single Ping", action='store_true')
    parser.add_argument("-sA", help="Scan all ports", action='store_true')
    parser.add_argument("-sO", help="Detect the operative system with the TTL value", action='store_true')
    parser.add_argument("-C", "--capture",  help="Capture the network traffic to specific IP", action='store_true')
    parser.add_argument("-m", "--macchange",help="Change randomly the mac", action='store_true')
    parser.add_argument("-p", "--port",help="Set the port range",action='store_true')
    parser.add_argument("-i", "--interface",help="Set the interface",required=False)
    parser.add_argument("-t", "--target",help="Target IP",required=True)
    options = parser.parse_args(args)
    return options

def capture_traffic(target):
	try:
		os.system("sudo tcpdump -i any -tttt dst "+ target)
	except KeyboardInterrupt:
		print("Exiting....")
		sys.exit(1)
		
		
def get_current_mac(interface):
     ifconfig_result = subprocess.check_output(["ifconfig", interface])
     regex_mac_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
     if regex_mac_search_result:
         return regex_mac_search_result.group(0)
     else:
         print("[-] Error: could not read MAC address.")

def change_mac(interface, new_mac):
     print("[+] Changing MAC address for " + interface + " to " + new_mac)
     subprocess.call(["ifconfig", interface, "down"])
     subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
     subprocess.call(["ifconfig", interface, "up"])

def setportrange():
	while True:
		print("")
		min_port = input("Minimun port number: ")
		max_port = input("Maximun port number: ")
		print("")
		if int(min_port) > 0 and int(max_port) < 65536:
			return range(int(min_port),int(max_port))
			
def scanport(Port,target):
	SYNACK = 0x12
	RSTACK = 0x14
	srcport = RandShort()
	SYNACKpkt = IP(dst = target)/TCP(sport = srcport,dport = port,flags = "S",seq=0,ack=0)
	response = sr(SYNACKpkt,timeout=1,verbose=0)
	try:
		if response.getlayer(TCP).flags == SYNACK:
			return True
		else: 
			return False
		RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
		send(RSTpkt)
	except:
		pass

def checkforRoot():
	if os.geteuid() != 0:
		print("You need root privileges to run this function")
		sys.exit(1)
	
def scanrangeport(target,ports):
	start_clock = datetime.now()
	counter = 1000;
	count = 0
	print("[*] Scanning Started at "+strftime("%H:%M:%S")+"\n")
	for port in ports:
		try:
			if count == counter:
				print("[+] "+count+"scanned ports")
				counter+=1000
			status = scanport(port,target)
			count += 1
			if status == True:
				print("Port "+str(port)+": OPEN")
		except KeyboardInterrupt:
			print("Exiting....")
			sys.exit(1)	
	print("Scanning Finished!")
	print("Scan Time: "+str(datetime.now()-start_clock))
	
def checkerror(opts):
	if opts.sP and opts.sO:
		print("You cannot use -sP (single Ping) with -sO (TTL SO detect)")
		sys.exit(1)
	if opts.sA and opts.port: 
		print("You cannot use -sA (All ports scan) with -p (Port range)")
		sys.exit(1)
	if opts.macchange and opts.interface is None:
		print("You need to define interface -i to use macchanger")
		sys.exit(1)

def main():
	opts = getOptions()
	checkerror(opts)
	print(opts)
	#PING TYPE
	if opts.sP:
		host_is_up(opts.target)
	elif opts.sO:
		return_ttl_so(opts.target)
	#PORT SCAN TYPE
	if opts.sA:
		checkforRoot()
		scanrangeport(target,range(1,65535))
	elif opts.port:
		checkforRoot()
		puertos = setportrange()
		scanrangeport(opts.target,puertos)
	#MISC UTILS
	if opts.macchange:
		print("change the mac")
	if opts.capture:
		capture_traffic(opts.target)
	
def host_is_up(target):
	response = os.system("ping  -c 1 "+target +"> /dev/null 2> /dev/null")
	if response == 0:
		print(target +" -> "+"host is up")
		return 0
	else:
		print(target + " -> "+"host is down")
		return 1

def return_ttl_so(target):
	try:
		ttl = return_ttl_number(target)
		ttl = int(ttl)
		so = return_ttl_so_name(ttl)
		print("[+] "+target+" -> "+str(ttl)+" -> "+so)
	except Exception:
		pass
def return_ttl_number(address):
	try:
		proc = subprocess.Popen(["ping %s -c 1" %address, " "],stdout=subprocess.PIPE, shell=True)
		(out,err) = proc.communicate();
		out = out.split()	
		out = re.findall(r"\d{1,3}",str(out[12]))
		return out[0]
	except Exception:
		pass

def return_ttl_so_name(ttl_number):
	if ttl_number >= 0 and ttl_number <= 64:
		return "Linux"
	elif ttl_number >= 65 and ttl_number <=128:
		return "Windows"
	else:	
		return "Uknown"



###inicia
if len(sys.argv) < 2:
	print("Usage: python3 "+sys.argv[0]+" --help")
	sys.exit(1)

if __name__ == "__main__":	
	target = sys.argv[1]	
	main()
