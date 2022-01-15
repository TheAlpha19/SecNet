#!/usr/bin/python3 

from optparse import OptionParser
import subprocess
import time
import os
import threading
import xml.etree.ElementTree as ET
from colorama import Fore
from colorama.ansi import Style

Banner = '''
                ░██████╗███████╗░█████╗░███╗░░██╗███████╗████████╗
                ██╔════╝██╔════╝██╔══██╗████╗░██║██╔════╝╚══██╔══╝
                ╚█████╗░█████╗░░██║░░╚═╝██╔██╗██║█████╗░░░░░██║░░░
                ░╚═══██╗██╔══╝░░██║░░██╗██║╚████║██╔══╝░░░░░██║░░░
                ██████╔╝███████╗╚█████╔╝██║░╚███║███████╗░░░██║░░░
                ╚═════╝░╚══════╝░╚════╝░╚═╝░░╚══╝╚══════╝░░░╚═╝░░░
                               Author: Nidhin [A19]
                        Github: https://github.com/TheAlpha19     
'''

print(Fore.RED + Banner + Style.RESET_ALL)

parser = OptionParser()
parser.add_option("-b", "--baseline", dest = "baseline", type = float, default = 6.5, help = "Baseline CVSS Score [Default: 6.5]")
parser.add_option("-r", "--refresh-time", dest = "rt", type = float, default = 12, help = "Time (in Hours) After Which All Internal Variables are Reset [Default: 12]")
parser.add_option("-s", "--sleep-time", dest = "st", type = int, default = 5, help = "Iteration Sleep Time (in Seconds; Higher Value = Longer Response Time to Newly Connected Clients and Clients in Lists) [Default: 5]")
parser.add_option("-d", "--debug", action = "store_true", dest = "debug", help = "Start SecNet in Debug Verbose Mode")

(options, args) = parser.parse_args()

processing_queue = []
whitelist = []
props = {}
prop_time = {}
threads = []
blacklist = []

init = time.time()
base = float(options.baseline)
rt = float(options.rt)
st = int(options.st)

def check_root():
	if os.getuid() != 0:
		print(Fore.RED + "[-] Script Must Be Ran As Root [-]\n" + Style.RESET_ALL)
		exit()

def run_command(cmd):
	cmd = cmd.split(" ")
	sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = sub.communicate()

	return out,err

def run_command_nosplit(cmd):
        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell = True)
        out, err = sub.communicate()

        return out,err

def scan(IP):
	run_command_nosplit("nmap -sV --script vulners.nse " + IP + " -oA /home/pi/SecNet/scans/" + IP)

	mytree = ET.parse('/home/pi/SecNet/scans/' + IP + '.xml')
	root = mytree.getroot()

	id_elem = ""; type_elem = ""; cvss = ""; flg = 1;

	for port in root.iter('port'):
		for tabs in port.iter('table'):
			for elem in tabs.iter('elem'):
				if elem.get('key') == "cvss":
					if float(elem.text) > base:			
						print(Fore.RED + "[-] Vulnerable IP {} Added to Blacklist [-]\n".format(IP) + Style.RESET_ALL)
						blacklist.append(props[IP]["MAC"])
						processing_queue.remove(props[IP]["MAC"])
						flg = 0
						return;
	
	if flg == 1:	
		whitelist.append(props[IP]["MAC"])
		print(Fore.GREEN + "[+] Secure IP {} Added to Whitelist [+]\n".format(IP) + Style.RESET_ALL)
		processing_queue.remove(props[IP]["MAC"])
	

check_root()

while True:
	out, err = run_command("hostapd_cli list_sta")	
	out_proper = out.decode().split("\n")[1:-1]

	for i in out_proper:
		if i not in whitelist:
			if (i not in processing_queue) and (i not in blacklist):
				processing_queue.append(i)
				time.sleep(10)
				ip_raw, ip_err = run_command_nosplit("arp -an | grep " + i + " | awk '{print $2}' | tr -d '()'")
				ip = ip_raw.decode().split("\n")[0]
				print("Device with MAC {} requesting Access. Pushed To Processing Queue!".format(i))
				print("Device IP: {}\n".format(ip))

				if (((time.time() - init)/60)/60) >= rt:
					processing_queue = []
					whitelist = []
					props = {}
					prop_time = {}
					threads = []
					blacklist = []
					init = time.time()

				props[ip] = {"MAC": i}
				prop_time[i] = {"Conn_Time": time.time()}

				time.sleep(2)

				t = threading.Thread(target = scan, args = (ip,))
				t.start()

				threads.append(t)

			if i in blacklist:
				print(Fore.RED + "Device with MAC {} is blacklisted! Deauthenticating!\n".format(i) + Style.RESET_ALL)
				out, err = run_command("hostapd_cli deauthenticate {}".format(i))
				if (((time.time() - prop_time[i]["Conn_Time"])/60)/60) >= 2:
					prop_time.remove(i)
					blacklist.remove()
					
	time.sleep(st)

	if options.debug:
		print(Fore.BLUE + "Processing Queue: {}\nProperties: {}\nBlackList: {}\nWhitelist: {}\n"
							.format(processing_queue,props, blacklist, whitelist) + Style.RESET_ALL)

	for thread in threads:
		if not thread.is_alive():
			thread.join()
			threads.remove(thread)
