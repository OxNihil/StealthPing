#!/usr/bin/python

import subprocess,re,sys,os
from datetime import datetime
from time import strftime
from scapy.all import *
import socket 
import argparse

##GLOBAL VARS
natscan = False

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-sP", help="single Ping", action='store_true')
    parser.add_argument("-sA", help="Scan all ports", action='store_true')
    parser.add_argument("-sO", help="Detect the operative system with the TTL value", action='store_true')
    parser.add_argument("-p", "--port",help="Set the port range",action='store_true')
    parser.add_argument("--top-ports",help="Scan the most common ports",action='store_true')
    parser.add_argument("--nat",help="Detect nated ports", action='store_true')
    parser.add_argument("-m", "--macchange",help="Change randomly the mac", action='store_true')
    parser.add_argument("-i", "--interface",help="Set the interface",required=False)
    parser.add_argument("-C", "--capture",  help="Capture the network traffic to specific IP", action='store_true')
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
     regex_mac_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
     if regex_mac_search_result:
         return regex_mac_search_result.group(0)
     else:
         print("[-] Error: could not read MAC address.")

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )
        
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

def mkicmppacket(ttl,dest):
	conf.verbose = 0
	p = IP(dst=dest, ttl=ttl)/ICMP()
	return p
  
def mktcppacket(ttl,dest,port):
	  conf.verbose = 0
	  p = IP(dst=dest, ttl=ttl)/TCP(dport=int(port), flags="S")
	  return p
      		
def detec_nated(target,port):
	ttl = 0 
	res = sr1(mkicmppacket(ttl,target))
	ttl+=1
	while res.type == 11:
		res = sr1(mkicmppacket(ttl,target))
		ttl+=1
		print ("+")
	nat_ttl = ttl
	ttl = ttl - 1  
	res = sr1(mktcppacket(ttl,target,port))
	while res.proto == 1 and res.type == 11:
		res = sr1(mktcppacket(ttl,target,port))
		ttl+=1
	if nat_ttl == ttl:
		print("Not NATed (" + str(nat_ttl) + ", " + str(ttl) + ")")
	else:
		print("This port is NATed. firewall TTL is " + str(nat_ttl) + ", TCP port TTL is " + str(ttl))

def scanport(port,target):
	try:
		global natscan
		SYNACK = 0x12
		RSTACK = 0x14
		srcport = RandShort()
		SYNACKpkt = IP(dst = target)/TCP(sport = srcport,dport = port,flags = "S",seq=0,ack=0)
		response = sr1(SYNACKpkt,timeout=2,verbose=0)
		if response is None:
			print(f"{target}:{port} is filtered (silently dropped).")
		elif(response.haslayer(TCP)):    
			if response.getlayer(TCP).flags == SYNACK:
				if natscan: #nat detection
					detec_nated(target,port)
				return True
			else: 
				return False
			RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
			send(RSTpkt)
	except KeyboardInterrupt:
		print("Exiting....")
		sys.exit(1)
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
				print("[+] "+str(count)+"scanned ports")
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
	if (opts.sA  == True or opts.port == True) and opts.top_ports == True:
		print("You cannot use -sA (All ports scan) or -p (Port range) whit --top-ports")
		sys.exit(1)
	

def main():
	global natscan
	topports=[21,22,23,25,53,69,80,110,143,443,5900]
	opts = getOptions()
	checkerror(opts)
	print(opts)
	#CHANGE MAC
	if opts.macchange:
		checkforRoot()
		print("[+] Current MAC: "+str(get_current_mac(opts.interface)))
		change_mac(opts.interface,rand_mac())	
	#natscan
	if opts.nat:	
		natscan = True
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
	elif opts.top_ports:
		checkforRoot()
		scanrangeport(opts.target,topports)
	#DEFAULT OPTION
	if opts.target is not None and (opts.sA == False and opts.sP == False 
	and opts.port == False and opts.sO == False
	and opts.top_ports == False and opts.nat == False):
		host_is_up(opts.target)
	#MISC UTILS
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

if len(sys.argv) < 2:
	print("Usage: python3 "+sys.argv[0]+" --help")
	sys.exit(1)

if __name__ == "__main__":	
	main()
