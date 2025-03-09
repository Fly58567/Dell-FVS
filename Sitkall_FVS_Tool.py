#===================================================================#
#       Tool Name: Sitkall MB FVS Tool                              #
#         Version: 0.1                                              #
#         Edit by: Fly   2018/11/28                                 #
#===================================================================#
import sys
import datetime
import subprocess
import os
import configparser
import time
import ctypes
import serial

global ROOT_DIR
ROOT_DIR = os.getcwd()

global PYTHON27_DIR
PYTHON27_DIR = os.path.join(ROOT_DIR, "Python27")

global LOG_DIR
LOG_DIR = os.path.join(ROOT_DIR, "Log")

global DIAGPRO_DIR
DIAGPRO_DIR = os.path.join(ROOT_DIR, "DiagPro")

global DDIAGS_DIR
DDIAGS_DIR = os.path.join(ROOT_DIR, "DDIAGS")

global FRU_DIR
FRU_DIR = os.path.join(ROOT_DIR, "FRU_Tool")

global RW_DIR
RW_DIR = os.path.join(ROOT_DIR, "RW")

global IPMITOOL_DIR
IPMITOOL_DIR = os.path.join(ROOT_DIR, "ipmitool")

global SFC_DIR
SFC_DIR = os.path.join(ROOT_DIR, "SFC")

global BIOS_DIR
BIOS_DIR = os.path.join(ROOT_DIR, "BIOS")

global USB_DIR
USB_DIR = os.path.join(ROOT_DIR, "USB")

global RACADM_DIR
RACADM_DIR = "C:\\Program Files\Dell\SysMgt\idrac"

global POWERSHELL
POWERSHELL = "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"

global COM_PORT
COM_PORT = "COM3"

global DEBUG_MODE
DEBUG_MODE = True

global FAIL_CONTINUE
FAIL_CONTINUE = True

global BIOS_VER
BIOS_VER = "99.2.8"

global CPLD_VER
CPLD_VER = "0.2.0"

global BMC_VER
BMC_VER = "3.00.50"

STD_OUTPUT_HANDLE = -11

FOREGROUND_BLACK     = 0x00
FOREGROUND_BLUE      = 0x01
FOREGROUND_GREEN     = 0x02
FOREGROUND_RED       = 0x04
FOREGROUND_INTENSITY = 0x08

FONT_WHITE  = 0
FONT_RED    = 1
FONT_GREEN  = 2
FONT_BLUE   = 3
FONT_YELLOW = 4

PASS_BANNER = """
########     ###     ######   ######     #### ####
##     ##   ## ##   ##    ## ##    ##    #### ####
##     ##  ##   ##  ##       ##          #### ####
########  ##     ##  ######   ######      ##   ##
##        #########       ##       ##
##        ##     ## ##    ## ##    ##    #### ####
##        ##     ##  ######   ######     #### ####
"""

FAIL_BANNER = """
########    ###    #### ##          #### ####
##         ## ##    ##  ##          #### ####
##        ##   ##   ##  ##          #### ####
######   ##     ##  ##  ##           ##   ##
##       #########  ##  ##
##       ##     ##  ##  ##          #### ####
##       ##     ## #### ########    #### ####
"""
#===============================================================================
class Color:
	std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

	def set_cmd_color(self, color, handle = std_out_handle):
		bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
		return bool

	def reset_color(self):
		self.set_cmd_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

	def print_red_text(self, print_text):
		self.set_cmd_color(FOREGROUND_RED | FOREGROUND_INTENSITY)
		print(print_text)
		self.reset_color()

	def print_green_text(self, print_text):
		self.set_cmd_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY)
		print(print_text)
		self.reset_color()

	def print_blue_text(self, print_text):
		self.set_cmd_color(FOREGROUND_BLUE | FOREGROUND_INTENSITY)
		print(print_text)
		self.reset_color()

	def print_yellow_text(self, print_text):
		self.set_cmd_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
		print(print_text)
		self.reset_color()

	def print_light_green_text(self, print_text):
		self.set_cmd_color(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
		print(print_text)
		self.reset_color()

	def print_purple_text(self, print_text):
		self.set_cmd_color(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY)
		print(print_text)
		self.reset_color()
#===============================================================================
def Banner(msg):
	line_0 = "#" + "="*78 + "#"
	line_1 = "#" + " "*78 + "#"

	msg_length = 0
	for i in range(len(msg)):
		if(32 <= int.from_bytes(msg[i].encode(errors = "ignore"), 'big') <= 126):
			msg_length = msg_length + 1
		else:
			msg_length = msg_length + 2

	x = int((len(line_0) - msg_length - 2)/2)

	if(msg_length%2 == 0):
		tmp_str = "#" + " "*x + msg + " "*x + "#"
	else:
		tmp_str = "#" + " "*x + msg + " "*x + " #"

	clr = Color()
	clr.print_light_green_text("")
	clr.print_light_green_text(line_0)
	clr.print_light_green_text(line_1)
	clr.print_light_green_text(tmp_str)
	clr.print_light_green_text(line_1)
	clr.print_light_green_text(line_0)
	clr.print_light_green_text("")
#===============================================================================
def Show_Pass():
	global PPID
	global MACLIST
	global UUT_STATIONID

	Log("PASS", FONT_GREEN)

	now = datetime.datetime.today()
	os.rename(LOG_FILE, os.path.join(LOG_DIR, "%s_PASS_%02d%02d-%02d%02d.txt"%(PPID, now.month, now.day, now.hour, now.minute)))

	clr = Color()
	clr.print_green_text(PASS_BANNER)

	config = configparser.ConfigParser()
	config.read(os.path.join(SFC_DIR, "SFC.ini"))
	config["UUT"]["result"] = "PASS"
	config["UUT"]["errormessage"] = "NA"
	config.write(open(os.path.join(SFC_DIR, "SFC.ini"), "w"))

	if(UUT_STATIONID != "DBG-001"):
		os.chdir(SFC_DIR)
		os.system("SFCTool.exe")
		os.chdir(ROOT_DIR)
		input("Press ENTER to Shutdown System!!\n")
		os.system("timeout /T 5 /NOBREAK")
		os.system("shutdown /s /t 1")

	os.system("pause")
#===============================================================================
def Show_Fail(error_msg):
	global PPID
	global MACLIST
	global UUT_STATIONID

	Log("FAIL: %s"%(error_msg), FONT_RED)

	now = datetime.datetime.today()
	os.rename(LOG_FILE, os.path.join(LOG_DIR, "%s_FAIL_%02d%02d-%02d%02d.txt"%(PPID, now.month, now.day, now.hour, now.minute)))

	clr = Color()
	clr.print_red_text(FAIL_BANNER)

	config = configparser.ConfigParser()
	config.read(os.path.join(SFC_DIR, "SFC.ini"))
	config["UUT"]["result"] = "FAIL"
	config["UUT"]["errormessage"] = error_msg
	config.write(open(os.path.join(SFC_DIR, "SFC.ini"), "w"))

	if(UUT_STATIONID != "DBG-001"):
		os.chdir(SFC_DIR)
		os.system("SFCTool.exe")
		os.chdir(ROOT_DIR)

	os.system("pause")
#===============================================================================
def Log(string, index):
	global LOG_FILE

	now = datetime.datetime.today()
	tmp = "[%04d/%02d/%02d %02d:%02d:%02d] %s\n"%(now.year, now.month, now.day, now.hour, now.minute, now.second, string)

	try:
		f = open(LOG_FILE, "a")
		f.write(tmp)
		f.close()
	except:
		print("Logging Error!!")
		return

	clr = Color()
	tmp = tmp[:-1]

	if(index == FONT_RED):
		clr.print_red_text(tmp)
	elif(index == FONT_GREEN):
		clr.print_green_text(tmp)
	elif(index == FONT_BLUE):
		clr.print_blue_text(tmp)
	elif(index == FONT_YELLOW):
		clr.print_yellow_text(tmp)
	else:
		try:
			print(tmp)
		except:
			print("Logging Error!!")
#===============================================================================
def Scan_PPID():
	Banner("Scan PPID Label")

	global PPID
	global LOG_FILE

	while(1):
		PPID = input("Please Scan Board PPID!!\n")
		if(PPID == "a"):
			PPID = "CN0SRT1SFCP0084G0004X00"
		if(len(PPID) == 23 and PPID[2:8] == "0SRT1S" and PPID[0:2] == "CN" and PPID[8:13] == "FCP00"):
			LOG_FILE = os.path.join(ROOT_DIR, "%s.txt"%PPID)
			Log("Sitkall Planar PPID!! (%s)"%(PPID), FONT_YELLOW)
			break
		else:
			print("PPID is Wrong, Please Scan Again!!")
#===============================================================================
def Scan_MAC():
	Banner("Scan MAC Label")

	global MACLIST
	global LOG_FILE

	while(1):
		MACLIST = input("Please Scan MAC List!!\n")
		if(MACLIST == "a"):
			MACLIST = "D0946658BFB3;D0946658BFB4;D0946658BFB5;D0946658BFB6;D0946658BFB7;D0946658BFB8;D0946658BFB9;D0946658BFBA"
		if(len(MACLIST) == 103):
			LOG_FILE = os.path.join(ROOT_DIR, "%s.txt"%MACLIST)
			Log("Sitkall Planar MAC List!! (%s)"%(MACLIST), FONT_YELLOW)
			break
		else:
			print("MAC List is Wrong, Please Scan Again!!")
#===============================================================================
def Enter_iDRAC_Kernel():
	'''Enter iDRAC Kernel'''

	global BMC_VER

	print("Waiting for enter iDRAC kernel!! (FW Version: %s)"%(BMC_VER))
	'''timeout_5s = 20
	for i in range(timeout_5s):
		print(("%s secs...")%(5*(timeout_5s - i)))
		time.sleep(5)'''

	for i in range(10):
		ret = Input_CMD("cat /etc/fw_ver")
		if(BMC_VER in ret[1]):
			Log("Enter iDRAC Linux Kernel", FONT_YELLOW)
			break

		if(i != 9):
			time.sleep(10)
			print(("%s secs...")%(10*(10 - i)))
		else:
			Log("Enter_iDRAC_Kernel Fail (TIMEOUT!!)", FONT_RED)
			return False

	Log("Enter_iDRAC_Kernel Pass", FONT_GREEN)
	return True
#===============================================================================
def Input_CMD_iDRAC(cmd):
	global s

	Log("Input iDRAC Command: %s"%(cmd), FONT_YELLOW)

	cmd = "%s\r"%(cmd)

	s.write(cmd.encode())
	#s.write(cmd.encode(errors = "ignore"))
	ret = s.readlines()
	for i in range(len(ret)):
		ret[i] = ret[i].decode().strip()
		#ret[i] = ret[i].decode(errors = "ignore").strip()
		Log("ret[%d] %s"%(i, ret[i]), FONT_WHITE)

	s.close()
	return ret
#===============================================================================
def Input_CMD_OS(cmd):
	Log("Input OS Command: %s"%(cmd), FONT_YELLOW)

	try:
		ret = subprocess.check_output(cmd, shell = True, universal_newlines = True).splitlines()
	except:
		Log("Input Command Fail (%s)"%(cmd), FONT_RED)
		return False

	time.sleep(2)
	for i in range(len(ret)):
		ret[i] = ret[i].strip()
		if(DEBUG_MODE):
			Log("ret[%02d] %s"%(i, ret[i]), FONT_WHITE)

	return ret
#===============================================================================
def Input_CMD_RW(cmd):
	global RW_DIR
	global ROOT_DIR

	os.chdir(RW_DIR)

	for i in ["cmd.txt", "out.txt"]:
		if(os.path.isfile(i) == True):
			os.remove(i)

	f = open("cmd.txt", "w")
	f.write(">%s\n"%(cmd))
	f.write(">RwExit\n")
	f.close()

	cmd1 = "rw.exe /command=cmd.txt /Min /Nologo /Logfile=out.txt"
	ret = Input_CMD_OS(cmd1)

	f = open("out.txt", "r")
	ret = f.readlines()
	f.close()

	os.chdir(ROOT_DIR)

	reg = int(ret[0].strip().split("=", 1)[1], 16)

	Log("RW Command: %s -> Output: 0x%02X"%(cmd, reg), FONT_YELLOW)

	return reg
#===============================================================================
def Check_FW_Version():
	'''Check Firmware Version (BIOS/CPLD/BMC)'''

	global IPMITOOL_DIR
	global ROOT_DIR
	global SFC_DIR
	global BIOS_VER
	global CPLD_VER
	global BMC_VER

	flag_bios = False
	flag_cpld = False
	flag_bmc = False

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_BIOS")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for i in ret:
		if("Name" in i):
			bios = i.split()[2]

	if(bios == BIOS_VER):
		flag_bios = True

	os.chdir(IPMITOOL_DIR)

	ret = Input_CMD_OS("ipmitool.exe -I wmi raw 0x30 0x33")
	if(ret == False):
		return False

	cpld = "%d.%d.%d"%(int(ret[0].split()[0]), int(ret[0].split()[1]), int(ret[0].split()[2]))
	if(cpld == CPLD_VER):
		flag_cpld = True

	ret = Input_CMD_OS("ipmitool.exe -I wmi raw 0x30 0xBF 0x01")
	if(ret == False):
		return False

	bmc = "%d.%02d.%d"%(int(ret[0].split()[0], 16), int(ret[0].split()[1], 16), int(ret[0].split()[3], 16))
	if(bmc == BMC_VER):
		flag_bmc = True

	os.chdir(ROOT_DIR)

	Log("BIOS Version: %s"%(bios), FONT_YELLOW)
	Log("CPLD Version: %s"%(cpld), FONT_YELLOW)
	Log("BMC  Version: %s"%(bmc), FONT_YELLOW)

	config = configparser.ConfigParser()
	config.read(os.path.join(SFC_DIR, "SFC.ini"))
	config["UUT"]["biosver"] = bios
	config["UUT"]["firmwarever"] = "[CPLD:%s][BMC:%s]"%(cpld, bmc)
	config.write(open(os.path.join(SFC_DIR, "SFC.ini"), "w"))

	if(flag_bios and flag_cpld and flag_bmc):
		Log("Check_FW_Version Pass", FONT_GREEN)
		return True
	else:
		if(flag_bios == False):
			Log("Check_FW_Version Fail (BIOS)", FONT_RED)
		if(flag_cpld == False):
			Log("Check_FW_Version Fail (CPLD)", FONT_RED)
		if(flag_bmc == False):
			Log("Check_FW_Version Fail (BMC)", FONT_RED)
		return False
#===============================================================================
def Check_SMBIOS_Info():
	'''Check SMBIOS Information (Type 0/1/2/3)'''

	global BIOS_VER

	flag_bios = False
	flag_baseboard = False
	flag_computersystem = False
	flag_computersystemproduct = False

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_BIOS")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for i in ret:
		if("Name" in i):
			bios_ver = i.split()[2]
		if("Manufacture" in i):
			bios_manufacture = i.split(maxsplit = 2)[2]

	if(bios_ver == BIOS_VER and bios_manufacture == "Dell Inc."):
		flag_bios = True

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_BaseBoard")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for i in ret:
		if("Manufacture" in i):
			baseboard_manufacture = i.split(maxsplit = 2)[2]

	if(baseboard_manufacture == "Dell Inc."):
		flag_baseboard = True

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_ComputerSystem")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for i in ret:
		if("Manufacture" in i):
			computersystem_manufacture = i.split(maxsplit = 2)[2]
		if("Model" in i):
			computersystem_model = i.split(maxsplit = 2)[2]
		if("TotalPhysicalMemory " in i):
			computersystem_memory = int(i.split(maxsplit = 2)[2])

	if(computersystem_manufacture == "Dell Inc." and computersystem_model == "PowerEdge Sitkall" and computersystem_memory == 50132873216):
		flag_computersystem = True
	
	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_ComputerSystemProduct")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for i in ret:
		if("Name" in i):
			computersystemproduct_name = i.split(maxsplit = 2)[2]
		if("Vendor" in i):
			computersystemproduct_vendor = i.split(maxsplit = 2)[2]

	if(computersystemproduct_name == "PowerEdge Sitkall" and computersystemproduct_vendor == "Dell Inc."):
		flag_computersystemproduct = True

	if(flag_bios and flag_baseboard and flag_computersystem and flag_computersystemproduct):
		Log("Check_SMBIOS_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_bios == False):
			Log("Check_SMBIOS_Info Fail (BIOS)", FONT_RED)
		if(flag_baseboard == False):
			Log("Check_SMBIOS_Info Fail (Baseboard)", FONT_RED)
		if(flag_computersystem == False):
			Log("Check_SMBIOS_Info Fail (ComputerSystem)", FONT_RED)
		if(flag_computersystemproduct == False):
			Log("Check_SMBIOS_Info Fail (ComputerSystemProduct)", FONT_RED)
		return False
#===============================================================================
def Program_MB_FRU():
	'''Program MB FRU via FRU_Tool.py'''

	global COM_PORT
	global PPID
	global FRU_DIR
	global ROOT_DIR

	flag = False

	os.chdir(FRU_DIR)

	ret = subprocess.call("python FRU_Tool.py --com %s  --ppid %s"%(COM_PORT, PPID))

	if(ret == 0):
		flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("Program_MB_FRU Pass", FONT_GREEN)
		return True
	else:
		Log("Program_MB_FRU Fail", FONT_RED)
		return False
#===============================================================================
def Update_BMC_MAC():
	'''Update BMC MAC'''
	
	global MACLIST

	Log("BMC MAC List = %s"%(MACLIST.split('\n')), FONT_YELLOW)
	MAC_ETH0 = ''.join(MACLIST[00+i:00+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH1 = ''.join(MACLIST[13+i:13+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH2 = ''.join(MACLIST[26+i:26+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH3 = ''.join(MACLIST[39+i:39+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH4 = ''.join(MACLIST[52+i:52+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH5 = ''.join(MACLIST[65+i:65+i+2] + ':' for i in range(0,12,2)).strip(':')

	# Program BMC MAC
	#
	cmd = ''
	# '''
	flag = False
	while True:
		Input_CMD_iDRAC('mac read\n')
		while (Input_CMD_iDRAC.bufferIsEmpty() == False):
			line = Input_CMD_iDRAC(display=False)
			if MAC_ETH0.strip() in line:
				log.info('Already Program MAC Address!! - eth0 = {0}'.format(MAC_ETH0),subject='BMC MAC')
				flag = True
				break
		if (flag == True):
			break
		elif (cmd != ''):
			return status.FAIL_IDRAC_MAC_PROGRAM
	# '''
	cmd = 'mac {0} 6\n'.format(MAC_ETH0)
	ret = Input_CMD_iDRAC(cmd)
	if(ret == False):
		return False
	Log("Program MAC Address = %s-%s!!"%(MAC_ETH0, MAC_ETH3), FONT_YELLOW)

	ret = Input_CMD_iDRAC("setenv ethaddr %s\n"%(MAC_ETH0))
	if(ret == False):
		Log("Update_BMC_MAC Fail", FONT_RED)
		return False
		
	ret = Input_CMD_iDRAC("setenv eth1addr %s\n"%(MAC_ETH1))
	if(ret == False):
		Log("Update_BMC_MAC Fail", FONT_RED)
		return False
		
	ret = Input_CMD_iDRAC("setenv eth2addr %s\n"%(MAC_ETH2))
	if(ret == False):
		Log("Update_BMC_MAC Fail", FONT_RED)
		return False
		
	ret = Input_CMD_iDRAC("setenv eth3addr %s\n"%(MAC_ETH3))
	if(ret == False):
		Log("Update_BMC_MAC Fail", FONT_RED)
		return False
		
	ret = Input_CMD_iDRAC("saveenv\n")
	if(ret == False):
		Log("Update_BMC_MAC Fail", FONT_RED)
		return False
			
	'''
	while (self.uart.bufferIsEmpty() == False):
		line = self.uart.read_str(display=False)
		if '14G >' == line:
			break

	return status.SUCCESS
	'''
	
	Log("Update_BMC_MAC Pass", FONT_GREEN)
	return True
#===============================================================================
def Check_BMC_MAC():	
	'''Check BMC MAC'''
	
	global MACLIST
	
	MAC_ETH0 = ''.join(MACLIST[00+i:00+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH1 = ''.join(MACLIST[13+i:13+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH2 = ''.join(MACLIST[26+i:26+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH3 = ''.join(MACLIST[39+i:39+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH4 = ''.join(MACLIST[52+i:52+i+2] + ':' for i in range(0,12,2)).strip(':')
	MAC_ETH5 = ''.join(MACLIST[65+i:65+i+2] + ':' for i in range(0,12,2)).strip(':')

	flag0 = False
	flag2 = False
	flag3 = False
	
	ret = Input_CMD_iDRAC("ifconfig eth0\n")
	for index in range(len(ret)):
		if(MAC_ETH0.strip() in ret[index]):
			Log("eth0 addr Pass", FONT_GREEN)
			flag0 = True
	'''
	ret = Input_CMD_iDRAC("ifconfig eth2\n")
	for index in range(len(ret)):
		if(MAC_ETH2.strip() in ret[index]):
			Log("eth2 addr Pass", FONT_GREEN)
			flag2 = True
		
	ret = Input_CMD_iDRAC("ifconfig eth3\n")
	for index in range(len(ret)):
		if(MAC_ETH3.strip() in ret[index]):
			Log("eth3 addr Pass", FONT_GREEN)
			flag3 = True
	'''
	if(flag0 == True):
		Log("Check_BMC_MAC Pass", FONT_GREEN)
		return True
	else:		
		Log("Check_BMC_MAC Fail", FONT_RED)
		return False
	
#===============================================================================
def Check_Ethernet_MAC():
	'''Check Ethernet MAC'''
	
	global MACLIST
	
	MAC_ETH6 = ''.join(MACLIST[78+i:78+i+2] + '-' for i in range(0,12,2)).strip('-')
	MAC_ETH7 = ''.join(MACLIST[91+i:91+i+2] + '-' for i in range(0,12,2)).strip('-')

	cmd = 'ipconfig -all'
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		Log("Check_Ethernet_MAC Fail", FONT_RED)
		return False
		
	eth6_flag = False
	eth7_flag = False
	
	for line in ret:
		if MAC_ETH6 in line:
			eth6_flag = True
		elif MAC_ETH7 in line:
			eth7_flag = True
			
	if (eth6_flag == False or eth7_flag == False):
		Log("Check_Ethernet_MAC Fail", FONT_RED)
		return False
	
	Log("Check_Ethernet_MAC Pass", FONT_GREEN)
	return True
#===============================================================================
def Check_Ethernet_Link():
	'''Check Ethernet Link'''
	
	global MACLIST
	
	MAC_ETH6 = ''.join(MACLIST[78+i:78+i+2] + '-' for i in range(0,12,2)).strip('-')
	MAC_ETH7 = ''.join(MACLIST[91+i:91+i+2] + '-' for i in range(0,12,2)).strip('-')
	IPList = []
	EthNameList = []
	IP = 1
	EthName = ''
	
	# Set Ethernet IP Address
	for hwaddr in [MAC_ETH6, MAC_ETH7]:	
		cmd = "ipconfig -all"
		ret = Input_CMD_OS(cmd)
		if(ret == False):
			Log("Ethernet ipconfig Fail", FONT_RED)
			return False

		for i in range(0,len(ret)):
			if hwaddr in ret[i] and 'Physical Address' in ret[i]:
				EthName = ' '.join(ret[i-4].split(':')[0].split(' ')[2:])
				break
		
		if (EthName != ''):
			Log("Eth{0} Name: {1} set IP - 192.168.0.{2}".format(IP, EthName, IP), FONT_YELLOW)
			cmd = 'netsh interface ip set address "{0}" static 192.168.0.{1} 255.255.255.0'.format(EthName, IP)
			ret = Input_CMD_OS(cmd)
			if(ret == False):
				Log("Ethernet ip set Fail", FONT_RED)
				return False
			
			Log("Eth{0} Name: {1} set IP - 192.168.0.{2} Successfully".format(IP, EthName, IP), FONT_GREEN)
			
			EthNameList.append(EthName)                
			IPList.append('192.168.0.{0}'.format(IP))
		IP += 1
	
	if (IPList == []):
		Log("Ethernet ip set Fail", FONT_RED)
		return False

	# Cross Ping LOM connection
	for IP1 in IPList[::2]:
		IP1Location = IPList.index(IP1)
		if (IP1Location+1 >= len(IPList)):
			Log("The LOM IP2 Network not found", FONT_RED)
			return False
			
		for IP2 in IPList[IP1Location+1::]:
			time.sleep(5)
			cmd = 'ping -S {0} {1}'.format(IP1, IP2)
			ret = Input_CMD_OS(cmd)
			if(ret == False):
				Log("The LOM Network traffic Fail", FONT_RED)
				return False
			
	# delete ip address
	IP = 1
	for EthName in EthNameList:
		cmd = 'netsh interface ip delete address \"{0}\" addr=192.168.0.{1}'.format(EthName, IP)
		ret = Input_CMD_OS(cmd)
		if(ret == False):
			Log("Delete Ethernet address Fail", FONT_RED)
			return False
		IP += 1        
	
	Log("Check_Ethernet_Link Pass", FONT_GREEN)
	return True
#===============================================================================	
def Check_CPU_Info():
	'''Check CPU Information'''

	flag_caption = False
	flag_manufacturer = False
	flag_speed = False
	flag_socket_cpu1 = False
	flag_socket_cpu2 = False

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_Processor")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for i in ret:
		if("Caption" in i):
			caption = i.split(maxsplit = 2)[2]
			if(caption == "Intel64 Family 6 Model 85 Stepping 4"):
				flag_caption = True
			else:
				flag_caption = False
		if("Manufacturer" in i):
			manufacturer = i.split(maxsplit = 2)[2]
			if(manufacturer == "GenuineIntel"):
				flag_manufacturer = True
			else:
				flag_manufacturer = False
		if("MaxClockSpeed" in i):
			speed = i.split(maxsplit = 2)[2]
			if(speed == "1995"):
				flag_speed = True
			else:
				flag_speed = False
		if("SocketDesignation" in i):
			socket = i.split(maxsplit = 2)[2]
			if(socket == "CPU1"):
				flag_socket_cpu1 = True

	if(flag_caption and flag_manufacturer and flag_speed and flag_socket_cpu1):
		Log("Check_CPU_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_caption == False):
			Log("Check_CPU_Info Fail (CPU Caption)", FONT_RED)
		if(flag_manufacturer == False):
			Log("Check_CPU_Info Fail (CPU Manufacturer)", FONT_RED)
		if(flag_speed == False):
			Log("Check_CPU_Info Fail (CPU Speed)", FONT_RED)
		if(flag_socket_cpu1 == False):
			Log("Check_CPU_Info Fail (CPU1 Presence)", FONT_RED)
		return False
#===============================================================================
def Check_Cache_Info():
	'''Check Cache Information'''

	flag_cache_0_size = False
	flag_cache_0_status = False
	flag_cache_1_size = False
	flag_cache_1_status = False
	flag_cache_2_size = False
	flag_cache_2_status = False
	flag_cache_3_size = False
	flag_cache_3_status = False
	flag_cache_4_size = False
	flag_cache_4_status = False
	flag_cache_5_size = False
	flag_cache_5_status = False

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_CacheMemory")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for index in range(len(ret)):
		if("DeviceID" in ret[index] and ret[index].split(maxsplit = 2)[2] == "Cache Memory 0"):
			if(ret[index + 1].split(maxsplit = 2)[2] == "1024"):
				flag_cache_0_size = True
			if(ret[index + 5].split(maxsplit = 2)[2] == "OK"):
				flag_cache_0_status = True
		if("DeviceID" in ret[index] and ret[index].split(maxsplit = 2)[2] == "Cache Memory 1"):
			if(ret[index + 1].split(maxsplit = 2)[2] == "16384"):
				flag_cache_1_size = True
			if(ret[index + 5].split(maxsplit = 2)[2] == "OK"):
				flag_cache_1_status = True
		if("DeviceID" in ret[index] and ret[index].split(maxsplit = 2)[2] == "Cache Memory 2"):
			if(ret[index + 1].split(maxsplit = 2)[2] == "22528"):
				flag_cache_2_size = True
			if(ret[index + 5].split(maxsplit = 2)[2] == "OK"):
				flag_cache_2_status = True

	if(flag_cache_0_size and flag_cache_0_status and flag_cache_1_size and flag_cache_1_status and flag_cache_2_size and flag_cache_2_status):
		Log("Check_Cache_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_cache_0_size == False):
			Log("Check_Cache_Info Fail (Cache0 Size)", FONT_RED)
		if(flag_cache_0_status == False):
			Log("Check_Cache_Info Fail (Cache0 Status)", FONT_RED)
		if(flag_cache_1_size == False):
			Log("Check_Cache_Info Fail (Cache1 Size)", FONT_RED)
		if(flag_cache_1_status == False):
			Log("Check_Cache_Info Fail (Cache1 Status)", FONT_RED)
		if(flag_cache_2_size == False):
			Log("Check_Cache_Info Fail (Cache2 Size)", FONT_RED)
		if(flag_cache_2_status == False):
			Log("Check_Cache_Info Fail (Cache2 Status)", FONT_RED)
		return False
#===============================================================================
def Check_Memory_Info():
	'''Check Memory Information'''
	global ROOT_DIR

	flag_presence = True
	flag_size = True
	flag_speed = True

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_PhysicalMemory")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False
			
	dimm_locator_list = [
	"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13", "A14", "A15", "A16"]
	
	dimm_list = dimm_locator_list[:]
	
	for i in dimm_locator_list:
		for index in range(len(ret)):
			if("Capacity" in ret[index] and ret[index + 5].split(maxsplit = 2)[2] == i):
				size = ret[index].split(maxsplit = 2)[2]			
				speed = ret[index + 23].split(maxsplit = 2)[2]
				Log("===================================================", FONT_YELLOW)
				Log("DIMM %s Size: %s"%(i, size), FONT_YELLOW)
				Log("DIMM %s Speed: %s"%(i, speed), FONT_YELLOW)
				Log("===================================================", FONT_YELLOW)
				if(size != "4294967296"):
					flag_size = False
				if(speed != "2133"):
					flag_speed = False
				if(flag_size and flag_speed):
					dimm_list.remove(i)
	
	if(len(dimm_list) > 0):
		flag_presence = False
		msg = ""
		for i in dimm_list:
			msg = msg + "%s,"%(i)
		Log("DIMM [%s] Error!!"%(msg[:len(msg)-1]), FONT_RED)
		
	os.chdir(ROOT_DIR)

	if(flag_presence and flag_size and flag_speed):
		Log("Check_Memory_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_presence == False):
			Log("Check_Memory_Info Fail (DIMM Presence)", FONT_RED)
		if(flag_size == False):
			Log("Check_Memory_Info Fail (DIMM Size)", FONT_RED)
		if(flag_speed == False):
			Log("Check_Memory_Info Fail (DIMM Speed)", FONT_RED)
		return False
#===============================================================================
def DDIAGS_Memory_Info():
	'''Check Memory Information'''

	global DDIAGS_DIR
	global ROOT_DIR

	os.chdir(DDIAGS_DIR)

	ret = Input_CMD_OS("Memory.exe -conf")
	if(ret == False):
		return False

	flag_total_memory = False
	for i in ret:
		if("TotalMemory" in i and i.split()[0] == "TotalMemory" and i.split()[2] == "49152"):
			flag_total_memory = True

	dimm_locator_list = [
	"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13", "A14", "A15", "A16"]

	dimm_list = dimm_locator_list[:]

	flag_presence = True
	flag_size = True
	flag_speed = True
	flag_type = True

	for i in dimm_locator_list:
		for index in range(len(ret)):
			if("Name" in ret[index] and ret[index].split(maxsplit = 2)[2] == i):
				size = ret[index + 1].split(maxsplit = 2)[2]
				speed = ret[index + 7].split(maxsplit = 2)[2]
				type = ret[index + 2].split(maxsplit = 2)[2]
				Log("===================================================", FONT_YELLOW)
				Log("DIMM %s Size: %s"%(i, size), FONT_YELLOW)
				Log("DIMM %s Speed: %s"%(i, speed), FONT_YELLOW)
				Log("DIMM %s Type: %s"%(i, type), FONT_YELLOW)
				Log("===================================================", FONT_YELLOW)
				if(size != "4096 MB"):
					flag_size = False
				if(speed != "2133"):
					flag_speed = False
				if(type != "DDR4"):
					flag_type = False
				if(flag_size and flag_speed and flag_type):
					dimm_list.remove(i)
		#if((flag_presence and flag_size and flag_speed and flag_type) == False):
		#	break

	if(len(dimm_list) > 0):
		flag_presence = False
		msg = ""
		for i in dimm_list:
			msg = msg + "%s,"%(i)
		Log("DIMM [%s] Error!!"%(msg[:len(msg)-1]), FONT_RED)

	os.chdir(ROOT_DIR)

	if(flag_total_memory and flag_presence and flag_size and flag_speed and flag_type):
		Log("DDIAGS_Memory_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_total_memory == False):
			Log("DDIAGS_Memory_Info Fail (Total Memory Size)", FONT_RED)
		if(flag_presence == False):
			Log("DDIAGS_Memory_Info Fail (DIMM Presence)", FONT_RED)
		if(flag_size == False):
			Log("DDIAGS_Memory_Info Fail (DIMM Size)", FONT_RED)
		if(flag_speed == False):
			Log("DDIAGS_Memory_Info Fail (DIMM Speed)", FONT_RED)
		if(flag_type == False):
			Log("DDIAGS_Memory_Info Fail (DIMM Type)", FONT_RED)
		return False
#===============================================================================
def Check_HDD_Presence():
	'''Check_HDD_Presence'''
	flag = True
		
	'''SATA A (00:11.5 Byte 0x96)'''
	ret = Input_CMD_RW("Rpcie 0x00 0x11 0x05 0x96")

	#BP sSATA_2 ~ sSATA5
	for i in range(0,4):
		tmp = 0x4 << i
		if(ret & tmp == tmp):
			Log("Find sSATA_%d"%(i+2), FONT_GREEN)
		else:
			Log("Couldn't Find sSATA_%d"%(i+2), FONT_RED)
			flag = False

	'''SATA B (00:17.0 Byte 0x96)'''
	ret = Input_CMD_RW("Rpcie 0x00 0x17 0x00 0x96")

	#BP SATA_0 ~ SATA_3
	for i in range(0,4):
		tmp = 0x1 << i
		if(ret & tmp == tmp):
			Log("Find SATA_%d"%(i), FONT_GREEN)
		else:
			Log("Couldn't Find SATA_%d"%(i), FONT_RED)
			flag = False
			
	'''SATA C (00:17.0 Byte 0x96)'''
	ret = Input_CMD_RW("Rpcie 0x00 0x17 0x00 0x96")

	#BP SATA_4 ~ SATA_7
	for i in range(4,8):
		tmp = 0x1 << i
		if(ret & tmp == tmp):
			Log("Find SATA_%d"%(i), FONT_GREEN)
		else:
			Log("Couldn't Find SATA_%d"%(i), FONT_RED)
			flag = False
			
	if(flag):
		Log("Check_HDD_Presence Pass", FONT_GREEN)
		return True
	else:
		Log("Check_HDD_Presence Fail", FONT_RED)
		return False
#===============================================================================
def Check_HDD_Info():
	'''Check HDD Information (WMI)'''

	os.chdir(DDIAGS_DIR)
	
	#DeviceName              = HDD0
	#DeviceMnemonic          = HDD:0
	#DeviceMnemonic          = HDDSATA:0
	#DeviceMnemonic          = HDDATA:0
	#DeviceTypeString        = HDDSATA
	#Commodity               = hard_drive
	#mSATADevice             = No
	#PhysicalDrive           = 0
	#Model                   = HGST HUS726060ALE614
	#Vendor                  = HGST
	#FwRev                   = APGNW517
	#SerialNumber            = NAG95YJY
	#Capacity                = 6001175MB
	
	devicename = []
	flag_hdd_model = []
	flag_hdd_vendor = []
	flag_hdd_size = []

	ret = Input_CMD_OS("Disk.exe -conf")
	if(ret == False):
		return False
			
	devicecount = 0
	for index in range(len(ret)):
		if("DeviceName" in ret[index] and "HDD" in ret[index].split(maxsplit = 2)[2][:3] and "HDDUSB" not in ret[index].split(maxsplit = 2)[2][:6] and "HDDCON" not in ret[index].split(maxsplit = 2)[2][:6]):
			devicename.append(ret[index].split(maxsplit = 2)[2])
			model = ret[index + 8].split(maxsplit = 2)[2]
			vendor = ret[index + 9].split(maxsplit = 2)[2]
			if("PPID" in ret[index + 12]):
				size = ret[index + 13].split(maxsplit = 2)[2]
			else:
				size = ret[index + 12].split(maxsplit = 2)[2]
			flag_hdd_model.append(False)
			flag_hdd_vendor.append(False)
			flag_hdd_size.append(False)
			if(model == "HGST HUS726060ALE614"):
				flag_hdd_model[devicecount] = True
				if(vendor == "HGST"):
					flag_hdd_vendor[devicecount] = True
				if(size == "6001175MB"):
					flag_hdd_size[devicecount] = True	
			elif(model == "Hitachi HUA723020ALA640"):
				flag_hdd_model[devicecount] = True
				if(vendor == "Hitachi"):
					flag_hdd_vendor[devicecount] = True
				if(size == "2000398MB"):
					flag_hdd_size[devicecount] = True
			elif(model == "Hitachi HUA722010CLA330"):
				flag_hdd_model[devicecount] = True
				if(vendor == "Hitachi"):
					flag_hdd_vendor[devicecount] = True
				if(size == "1000204MB"):
					flag_hdd_size[devicecount] = True
			elif(model == "ST320LT012-1DG14C"):
				flag_hdd_model[devicecount] = True
				if(vendor == "SEAGATE"):
					flag_hdd_vendor[devicecount] = True
				if(size == "320072MB"):
					flag_hdd_size[devicecount] = True
			elif(model == "ST1000NM0011"):
				flag_hdd_model[devicecount] = True
				if(vendor == "SEAGATE"):
					flag_hdd_vendor[devicecount] = True
				if(size == "1000204MB"):
					flag_hdd_size[devicecount] = True
			elif(model == "ST32000644NS"):
				flag_hdd_model[devicecount] = True
				if(vendor == "SEAGATE"):
					flag_hdd_vendor[devicecount] = True
				if(size == "2000398MB"):
					flag_hdd_size[devicecount] = True
			devicecount += 1

	os.chdir(ROOT_DIR)
	
	result = True
	for index in range(devicecount):
		if(flag_hdd_model[index] == False):
			Log(("Check_HDD_Info Fail (%s)(Model)"%devicename[index]), FONT_RED)
			result = False
		if(flag_hdd_vendor[index] == False):
			Log(("Check_HDD_Info Fail (%s)(Vendor)"%devicename[index]), FONT_RED)
			result = False
		if(flag_hdd_size[index] == False):
			Log(("Check_HDD_Info Fail (%s)(Size)"%devicename[index]), FONT_RED)
			result = False
	
	if(result):
		Log("Check_HDD_Info Pass", FONT_GREEN)

	return result
	
	#BP Slot0 (OS SATA HDD)
	#DeviceID   : \\.\PHYSICALDRIVE0
	#Model      : SAMSUNG HE502HJ
	#Size       : 500105249280
	#Caption    : SAMSUNG HE502HJ

	'''
	flag_presence = False
	flag_type = True
	flag_size = True

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_DiskDrive")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for index in range(0,1):
		flag_presence = False
		for i in range(len(ret)):
			if("DeviceID" in ret[i] and ret[i].split(":", 1)[1].strip() == "\\\\.\PHYSICALDRIVE%d"%(index)):
				Log("Find HDD%d"%(index), FONT_YELLOW)
				flag_presence = True

				#For OS HDD
				if(index == 0):
					type = "HGST HUS726060ALE614"
					size = "6001172513280"

				if(ret[i + 1].split(":", 1)[1].strip() != type):
					print(type)
					flag_type = False
				if(ret[i + 2].split(":", 1)[1].strip() != size):
					print(size)
					flag_size = False

				break
		if((flag_presence and flag_type and flag_size) == False):
			break

	if(flag_presence and flag_type and flag_size):
		Log("Check_HDD_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_presence == False):
			Log("Check_HDD_Info Fail (Presence)", FONT_RED)
		if(flag_type == False):
			Log("Check_HDD_Info Fail (Type)", FONT_RED)
		if(flag_size == False):
			Log("Check_HDD_Info Fail (Size)", FONT_RED)
		return False
	'''
#===============================================================================
def Check_NVMe_Info():
	'''Check NVMe Information (WMI)'''

	#BP Slot1~5 (NVMe PCIe SSD)
	#DeviceID   : \\.\PHYSICALDRIVE[1, 2, 3, 4, 5]
	#Model      : NVMe INTEL SSDPEKKW12
	#Size       : 128034708480

	flag_presence = False
	flag_type = True
	flag_size = True

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_DiskDrive")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for index in range(1, 6):
		flag_presence = False
		for i in range(len(ret)):
			if("DeviceID" in ret[i] and ret[i].split(":", 1)[1].strip() == "\\\\.\PHYSICALDRIVE%d"%(index)):
				Log("Find NVME%d"%(index), FONT_YELLOW)
				flag_presence = True

				type = "NVMe INTEL SSDPEKKW12"
				size = "128034708480"

				if(ret[i + 1].split(":", 1)[1].strip() != type):
					print(type)
					flag_type = False
				if(ret[i + 2].split(":", 1)[1].strip() != size):
					print(size)
					flag_size = False

				break
		if((flag_presence and flag_type and flag_size) == False):
			break

	if(flag_presence and flag_type and flag_size):
		Log("Check_NVMe_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_presence == False):
			Log("Check_NVMe_Info Fail (Presence)", FONT_RED)
		if(flag_type == False):
			Log("Check_NVMe_Info Fail (Type)", FONT_RED)
		if(flag_size == False):
			Log("Check_NVMe_Info Fail (Size)", FONT_RED)
		return False
#===============================================================================
def Check_BOSS_Info():
	'''Check BOSS M.2 NVMe SSD Information (WMI)'''

	#BOSS (M.2 NVMe SSD)
	#DeviceID   : \\.\PHYSICALDRIVE[6, 7]
	#Model      : NVMe INTEL SSDPEKKW12
	#Size       : 128034708480

	flag_presence = False
	flag_type = True
	flag_size = True

	cmd = "%s \"Get-WmiObject %s | format-list\""%(POWERSHELL, "Win32_DiskDrive")
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for index in range(6, 8):
		flag_presence = False
		for i in range(len(ret)):
			if("DeviceID" in ret[i] and ret[i].split(":", 1)[1].strip() == "\\\\.\PHYSICALDRIVE%d"%(index)):
				Log("Find BOSS Slot%d"%(index), FONT_YELLOW)
				flag_presence = True

				type = "NVMe INTEL SSDPEKKW12"
				size = "128034708480"

				if(ret[i + 1].split(":", 1)[1].strip() != type):
					print(type)
					flag_type = False
				if(ret[i + 2].split(":", 1)[1].strip() != size):
					print(size)
					flag_size = False

				break
		if((flag_presence and flag_type and flag_size) == False):
			break

	if(flag_presence and flag_type and flag_size):
		Log("Check_BOSS_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_presence == False):
			Log("Check_BOSS_Info Fail (Presence)", FONT_RED)
		if(flag_type == False):
			Log("Check_BOSS_Info Fail (Type)", FONT_RED)
		if(flag_size == False):
			Log("Check_BOSS_Info Fail (Size)", FONT_RED)
		return False
#===============================================================================
def Check_USB_Device():
	'''Check_USB_Device'''

	global USB_DIR
	global ROOT_DIR

	flag = False

	os.chdir(USB_DIR)

	ret = Input_CMD_OS("RUSB.exe -Hub 4 -Dev 7 -Low 1 -Full 2 -High 8")
	if(ret == False):
		return False

	for i in ret:
		if("PASS!Final RUSB.EXE Test Status: 0x00000000" in i):
			flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("Check_USB_Device Pass", FONT_GREEN)
		return True
	else:
		Log("Check_USB_Device Fail", FONT_RED)
		return False
#===============================================================================
def Check_USB3_Device():
	'''Check Onboard/FIO USB3.0 Device'''

	os.chdir(DDIAGS_DIR)

	#Onboard: HDDUSB0
	#FIO    : HDDUSB1
	#Model                   = Transcend 16GB
	#Vendor                  = JetFlash
	#Capacity                = 15820MB

	devicename = []
	flag_usb_model = []
	flag_usb_vendor = []
	flag_usb_size = []

	ret = Input_CMD_OS("Disk.exe -conf")
	if(ret == False):
		return False
			
	devicecount = 0
	for index in range(len(ret)):
		if("DeviceName" in ret[index] and "HDDUSB" in ret[index].split(maxsplit = 2)[2][:6]):
			devicename.append(ret[index].split(maxsplit = 2)[2])
			model = ret[index + 6].split(maxsplit = 2)[2]
			vendor = ret[index + 7].split(maxsplit = 2)[2]
			size = ret[index + 10].split(maxsplit = 2)[2]
			flag_usb_model.append(False)
			flag_usb_vendor.append(False)
			flag_usb_size.append(False)
			if(model == "Cruzer Glide 3.0"):
				flag_usb_model[devicecount] = True
				if(vendor == "SanDisk"):
					flag_usb_vendor[devicecount] = True
				if(size == "15669MB"):
					flag_usb_size[devicecount] = True	
			elif(model == "IDSDM"):
				flag_usb_model[devicecount] = True
				if(vendor == "DELL"):
					flag_usb_vendor[devicecount] = True
				if(size == "1028MB"):
					flag_usb_size[devicecount] = True
			devicecount += 1

	os.chdir(ROOT_DIR)

	print(devicename)
	print(flag_usb_model)
	print(flag_usb_vendor)
	print(flag_usb_size)
	
	result = True
	for index in range(devicecount):
		if(flag_usb_model[index] == False):
			Log(("Check_USB3_Device Fail (%s)(Model)"%devicename[index]), FONT_RED)
			result = False
		if(flag_usb_vendor[index] == False):
			Log(("Check_USB3_Device Fail (%s)(Vendor)"%devicename[index]), FONT_RED)
			result = False
		if(flag_usb_size[index] == False):
			Log(("Check_USB3_Device Fail (%s)(Size)"%devicename[index]), FONT_RED)
			result = False
	
	if(result):
		Log("Check_USB3_Device Pass", FONT_GREEN)

	return result
#===============================================================================
def Check_PCH_Version():
	'''Check PCH Version (00:1F.00 Byte 0x08)'''

	flag = False

	ret = Input_CMD_RW("Rpcie 0x00 0x1F 0x00 0x08")
	print(ret)
	if(ret == int("0x09", 16)):
		flag = True

	if(flag):
		Log("Check_PCH_Version Pass", FONT_GREEN)
		return True
	else:
		Log("Check_PCH_Version Fail", FONT_RED)
		return False
#===============================================================================
def Check_Serial_Info():
	'''Check Serial Port Information'''

	global DDIAGS_DIR
	global ROOT_DIR

	os.chdir(DDIAGS_DIR)

	flag_com1 = False
	flag_com2 = False

	ret = Input_CMD_OS("Serial.exe -conf")
	if(ret == False):
		return False

	for i in ret:
		if("PortID" in i and "COM1" in i):
			flag_com1 = True
		if("PortID" in i and "COM2" in i):
			flag_com2 = True

	os.chdir(ROOT_DIR)

	if(flag_com1 and flag_com2):
		Log("Check_Serial_Info Pass", FONT_GREEN)
		return True
	else:
		if(flag_com1 == False):
			Log("Check_Serial_Info Fail (COM1)", FONT_RED)
		if(flag_com2 == False):
			Log("Check_Serial_Info Fail (COM2)", FONT_RED)
		return False
#===============================================================================
def DDIAGS_Memory_Test():
	'''DDIAGS_Memory_Test'''

	global DDIAGS_DIR
	global ROOT_DIR

	os.chdir(DDIAGS_DIR)

	ret = Input_CMD_OS("Memory.exe -f:21")
	if(ret == False):
		return False

	flag = False

	for i in range(len(ret)):
		if("Test Results" in ret[i]):
			if("Status: Pass" in ret[i+1]):
				flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("DDIAGS_Memory_Test Pass", FONT_GREEN)
		return True
	else:
		Log("DDIAGS_Memory_Test Fail", FONT_RED)
		return False
#===============================================================================
def DDIAGS_PCIe_Test():
	'''DDIAGS_PCIe_Test'''

	global DDIAGS_DIR
	global ROOT_DIR

	os.chdir(DDIAGS_DIR)

	ret = Input_CMD_OS("PCIe.exe -util:1")
	if(ret == False):
		return False

	flag = False

	for i in range(len(ret)):
		if("Test Results" in ret[i]):
			if("Status: Pass" in ret[i+1]):
				flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("DDIAGS_PCIe_Test Pass", FONT_GREEN)
		return True
	else:
		Log("DDIAGS_PCIe_Test Fail", FONT_RED)
		return False
#===============================================================================
def DDIAGS_Disk_Test():
	'''DDIAGS_Disk_Test'''

	global DDIAGS_DIR
	global ROOT_DIR

	os.chdir(DDIAGS_DIR)

	cmd = "disk.exe"

	#SATA*1
	for i in range(0, 12):
		cmd = cmd + " -d:HDD:%d"%(i)

	cmd = cmd + " -f:11"
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	flag = False

	for i in range(len(ret)):
		if("Test Results" in ret[i]):
			if("Status: Pass" in ret[i+1]):
				flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("DDIAGS_Disk_Test Pass", FONT_GREEN)
		return True
	else:
		Log("DDIAGS_Disk_Test Fail", FONT_RED)
		return False
#===============================================================================
def DDIAGS_Video_Test():
	'''DDIAGS_Video_Test'''

	global DDIAGS_DIR
	global ROOT_DIR

	os.chdir(DDIAGS_DIR)

	ret = Input_CMD_OS("Video.exe -f:00")
	if(ret == False):
		return False

	flag = False

	for i in range(len(ret)):
		if("Test Results" in ret[i]):
			if("Status: Pass" in ret[i+1]):
				flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("DDIAGS_Video_Test Pass", FONT_GREEN)
		return True
	else:
		Log("DDIAGS_Video_Test Fail", FONT_RED)
		return False
#===============================================================================
def DDIAGS_Serial_Test():
	'''DDIAGS_Serial_Test'''

	global DDIAGS_DIR
	global ROOT_DIR

	os.chdir(DDIAGS_DIR)

	ret = Input_CMD_OS("Serial.exe -d:SERIAL:0")
	if(ret == False):
		return False

	flag_com1 = False
	flag_com2 = False

	for i in range(len(ret)):
		if("Test Results" in ret[i]):
			if("Status: Pass" in ret[i+1]):
				flag_com1 = True

	ret = Input_CMD_OS("Serial.exe -d:SERIAL:1")
	if(ret == False):
		return False

	for i in range(len(ret)):
		if("Test Results" in ret[i]):
			if("Status: Pass" in ret[i+1]):
				flag_com2 = True

	os.chdir(ROOT_DIR)

	if(flag_com1 and flag_com2):
		Log("DDIAGS_Serial_Test Pass", FONT_GREEN)
		return True
	else:
		if(flag_com1 == False):
			Log("DDIAGS_Serial_Test Fail (COM1)", FONT_RED)
		if(flag_com2 == False):
			Log("DDIAGS_Serial_Test Fail (COM2)", FONT_RED)
		return False
#===============================================================================
def Get_PCIe_Info(bus, device, function):
	Log("Get PCIe Device Information [%02X:%02X.%02X]"%(bus, device, function), FONT_YELLOW)

	cmd = "RPCIE32 0x%02X 0x%02X 0x%02X 0x00"%(bus, device, function)
	ret = Input_CMD_RW(cmd)

	vendor_id = ret & 0x0000FFFF
	device_id = (ret & 0xFFFF0000) >> 16

	if(vendor_id == device_id == 0xFFFF):
		Log("Can't Find PCIe Device", FONT_RED)
		return (0xFFFF, 0xFFFF, 0xFF, 0xFF)

	cmd = "RPCIE 0x%02X 0x%02X 0x%02X 0x34"%(bus, device, function)
	index = Input_CMD_RW(cmd)

	while(1):
		cmd = "RPCIE16 0x%02X 0x%02X 0x%02X 0x%02X"%(bus, device, function, index)
		ret = Input_CMD_RW(cmd)
		cap_id = ret & 0x00FF
		temp_index = (ret & 0xFF00) >> 8

		if(cap_id == 0x10):
			Log("Find PCIe Capability ID (0x%02X)"%(index), FONT_GREEN)
			break
		if(temp_index == 0x00):
			Log("Can't Find PCIe Capability ID", FONT_RED)
			return (vendor_id, device_id, 0xFF, 0xFF)

		index = temp_index

	cmd = "RPCIE16 0x%02X 0x%02X 0x%02X 0x%02X"%(bus, device, function, index + 0x12)
	ret = Input_CMD_RW(cmd)
	link_speed = ret & 0x000F
	link_width = (ret & 0x03F0) >> 4

	Log("[%02X:%02X.%02X] Vendor ID = 0x%04X"%(bus, device, function, vendor_id), FONT_WHITE)
	Log("[%02X:%02X.%02X] Device ID = 0x%04X"%(bus, device, function, device_id), FONT_WHITE)
	Log("[%02X:%02X.%02X] Link Speed = Gen%d"%(bus, device, function, link_speed), FONT_WHITE)
	Log("[%02X:%02X.%02X] Link Width = x%d"%(bus, device, function, link_width), FONT_WHITE)

	return (vendor_id, device_id, link_speed, link_width)
#===============================================================================
def Check_PCIe_Info_X4_1():
	'''Check PCIe x4 Info [01:00.0] PCIe Gen3 x4'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x01, 0x00, 0x00)
	
	if(vendor_id == 0x10B5):
		flag_vendor_id = True
	if(device_id == 0x8724):
		flag_device_id = True
	if(link_speed == 3):
		flag_link_speed = True
	if(link_width == 4):
		flag_link_width = True
	
	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_X4_1 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_X4_1 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_X4_1 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_X4_1 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_X4_1 Fail (Link Width)", FONT_RED)
			
		return False	
#===============================================================================
def Check_PCIe_Info_X4_2():
	'''Check PCIe x4 Info [18:00.0] PCIe Gen3 x4'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x18, 0x00, 0x00)
	
	if(vendor_id == 0x10B5):
		flag_vendor_id = True
	if(device_id == 0x8724):
		flag_device_id = True
	if(link_speed == 3):
		flag_link_speed = True
	if(link_width == 4):
		flag_link_width = True
	
	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_X4_2 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_X4_2 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_X4_2 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_X4_2 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_X4_2 Fail (Link Width)", FONT_RED)
			
		return False	
#===============================================================================
def Check_PCIe_Info_X8():
	'''Check PCIe x8 Info [5E:00.0] PCIe Gen3 x8'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x5E, 0x00, 0x00)
	
	if(vendor_id == 0x8086):
		flag_vendor_id = True
	if(device_id == 0x2030):
		flag_device_id = True
	if(link_speed == 3):
		flag_link_speed = True
	if(link_width == 8):
		flag_link_width = True
	
	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_X8 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_X8 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_X8 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_X8 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_X8 Fail (Link Width)", FONT_RED)
			
		return False	
#===============================================================================
def Check_PCIe_Info_X16():
	'''Check PCIe x16 Info [AF:00.0] PCIe Gen3 x16'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0xAF, 0x00, 0x00)
	
	if(vendor_id == 0x10B5):
		flag_vendor_id = True
	if(device_id == 0x8724):
		flag_device_id = True
	if(link_speed == 3):
		flag_link_speed = True
	if(link_width == 16):
		flag_link_width = True
	
	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_X16 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_X16 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_X16 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_X16 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_X16 Fail (Link Width)", FONT_RED)
			
		return False	
#===============================================================================
def Check_PCIe_Info_OCP():
	'''Check PCIe x16 OCP Info [AF:00.0] PCIe Gen3 x16'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0xAF, 0x00, 0x00)
	
	if(vendor_id == 0x10B5):
		flag_vendor_id = True
	if(device_id == 0x8724):
		flag_device_id = True
	if(link_speed == 3):
		flag_link_speed = True
	if(link_width == 16):
		flag_link_width = True
	
	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_OCP Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_OCP Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_OCP Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_OCP Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_OCP Fail (Link Width)", FONT_RED)
			
		return False	
#===============================================================================
def Check_PCIe_Info_Riser1():
	'''Check Riser1 PCIe Info [3B:00.0] PCIe Gen3 x16'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x3B, 0x00, 0x00)

	if(vendor_id == 0x10B5):
		flag_vendor_id = True
	if(device_id == 0x8724):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x10):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_Riser1 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_Riser1 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_Riser1 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_Riser1 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_Riser1 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_Fab_A0():
	'''Check Fab_A0 PCIe Info [3B:00.0] (J_MEZZ_A)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x3B, 0x00, 0x00)

	if(vendor_id == 0x14E4):
		flag_vendor_id = True
	if(device_id == 0x16D2):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x08):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_Fab_A0 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_Fab_A0 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_Fab_A0 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_Fab_A0 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_Fab_A0 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_Fab_A1():
	'''Check Fab_A1 PCIe Info [3B:00.1] (J_MEZZ_A)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x3B, 0x00, 0x01)

	if(vendor_id == 0x14E4):
		flag_vendor_id = True
	if(device_id == 0x16D2):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x08):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_Fab_A1 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_Fab_A1 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_Fab_A1 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_Fab_A1 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_Fab_A1 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_Fab_B0():
	'''Check Fab_B0 PCIe Info [86:00.0] (J_MEZZ_B)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x86, 0x00, 0x00)

	if(vendor_id == 0x14E4):
		flag_vendor_id = True
	if(device_id == 0x16D2):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x08):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_Fab_B0 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_Fab_B0 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_Fab_B0 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_Fab_B0 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_Fab_B0 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_Fab_B1():
	'''Check Fab_B1 PCIe Info [86:00.1] (J_MEZZ_B)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x86, 0x00, 0x01)

	if(vendor_id == 0x14E4):
		flag_vendor_id = True
	if(device_id == 0x16D2):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x08):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_Fab_B1 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_Fab_B1 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_Fab_B1 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_Fab_B1 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_Fab_B1 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_Fab_C():
	'''Check Fab_C PCIe Info [D8:00.0] (J_MINI_MEZZ)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0xD8, 0x00, 0x00)

	if(vendor_id == 0x10B5):
		flag_vendor_id = True
	if(device_id == 0x8724):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x10):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_Fab_C Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_Fab_C Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_Fab_C Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_Fab_C Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_Fab_C Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_PERC():
	'''Check PREC PCIe Info [18:00.0] (J_PERC)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x18, 0x00, 0x00)

	if(vendor_id == 0x1000):
		flag_vendor_id = True
	if(device_id == 0x0097):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x08):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_PERC Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_PERC Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_PERC Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_PERC Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_PERC Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_NVMe_1():
	'''Check NVMe1 PCIe Info [1A:00.0] (J_AUX_0)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0x1A, 0x00, 0x00)

	if(vendor_id == 0x8086):
		flag_vendor_id = True
	if(device_id == 0xF1A5):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x04):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_NVMe_1 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_NVMe_1 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_NVMe_1 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_NVMe_1 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_NVMe_1 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_NVMe_2():
	'''Check NVMe2 PCIe Info [AF:00.0] (J_AUX_1)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0xAF, 0x00, 0x00)

	if(vendor_id == 0x8086):
		flag_vendor_id = True
	if(device_id == 0xF1A5):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x04):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_NVMe_2 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_NVMe_2 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_NVMe_2 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_NVMe_2 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_NVMe_2 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_NVMe_3():
	'''Check NVMe3 PCIe Info [B0:00.0] (J_AUX_1)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0xB0, 0x00, 0x00)

	if(vendor_id == 0x8086):
		flag_vendor_id = True
	if(device_id == 0xF1A5):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x04):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_NVMe_3 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_NVMe_3 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_NVMe_3 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_NVMe_3 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_NVMe_3 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_NVMe_4():
	'''Check NVMe4 PCIe Info [B1:00.0] (J_AUX_2)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0xB1, 0x00, 0x00)

	if(vendor_id == 0x8086):
		flag_vendor_id = True
	if(device_id == 0xF1A5):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x04):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_NVMe_4 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_NVMe_4 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_NVMe_4 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_NVMe_4 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_NVMe_4 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_PCIe_Info_NVMe_5():
	'''Check NVMe5 PCIe Info [B2:00.0] (J_AUX_2)'''

	flag_vendor_id = False
	flag_device_id = False
	flag_link_speed = False
	flag_link_width = False

	(vendor_id, device_id, link_speed, link_width) = Get_PCIe_Info(0xB2, 0x00, 0x00)

	if(vendor_id == 0x8086):
		flag_vendor_id = True
	if(device_id == 0xF1A5):
		flag_device_id = True
	if(link_speed == 0x03):
		flag_link_speed = True
	if(link_width == 0x04):
		flag_link_width = True

	if(flag_vendor_id and flag_device_id and flag_link_speed and flag_link_width):
		Log("Check_PCIe_Info_NVMe_5 Pass", FONT_GREEN)
		return True
	else:
		if(flag_vendor_id == False):
			Log("Check_PCIe_Info_NVMe_5 Fail (Vendor ID)", FONT_RED)
		if(flag_device_id == False):
			Log("Check_PCIe_Info_NVMe_5 Fail (Device ID)", FONT_RED)
		if(flag_link_speed == False):
			Log("Check_PCIe_Info_NVMe_5 Fail (Link Speed)", FONT_RED)
		if(flag_link_width == False):
			Log("Check_PCIe_Info_NVMe_5 Fail (Link Width)", FONT_RED)
		return False
#===============================================================================
def Check_BMC_Sensor():
	'''Check BMC Sensor (Inlet Temperature & CMOS Battery)'''

	flag_inlet_temp = False
	flag_battery = False

	os.chdir(RACADM_DIR)

	ret = Input_CMD_OS("racadm.exe getsensorinfo")
	if(ret == False):
		return False

	for i in ret:
		if("System Board Inlet Temp" in i and "Ok" in i):
			flag_inlet_temp = True
		if("System Board CMOS Battery" in i and "Ok" in i):
			flag_battery = True

	os.chdir(ROOT_DIR)

	if(flag_inlet_temp and flag_battery):
		Log("Check_BMC_Sensor Pass", FONT_GREEN)
		return True
	else:
		if(flag_inlet_temp == False):
			Log("Check_BMC_Sensor Fail (Inlet Temperature)", FONT_RED)
		if(flag_battery == False):
			Log("Check_BMC_Sensor Fail (CMOS Battery)", FONT_RED)
		return False
#===============================================================================

def Check_BMC_NCSI():
	'''Check_BMC_NCS message'''
	flag_dedicated = False
	flag_lom1 = False
	flag_lom2 = False
	flag_lom3 = False
	flag_lom4 = False
	
	os.chdir(RACADM_DIR)
	Input_CMD_OS("racadm.exe set iDRAC.NIC.Selection 1")
	ret = Input_CMD_OS("racadm.exe get iDRAC.NIC.Selection")
	if(ret == False):
		return False
		
	for i in ret:
		if("Dedicated" in i):
			flag_dedicated = True
			
	Input_CMD_OS("racadm.exe set iDRAC.NIC.Selection 2")
	ret = Input_CMD_OS("racadm.exe get iDRAC.NIC.Selection")
	if(ret == False):
		return False
		
	for i in ret:
		if("LOM1" in i):
			flag_lom1 = True
			
	Input_CMD_OS("racadm.exe set iDRAC.NIC.Selection 3")
	ret = Input_CMD_OS("racadm.exe get iDRAC.NIC.Selection")
	if(ret == False):
		return False
		
	for i in ret:
		if("LOM2" in i):
			flag_lom2 = True
	
	Input_CMD_OS("racadm.exe set iDRAC.NIC.Selection 4")
	ret = Input_CMD_OS("racadm.exe get iDRAC.NIC.Selection")
	if(ret == False):
		return False
		
	for i in ret:
		if("LOM3" in i):
			flag_lom3 = True
	
	Input_CMD_OS("racadm.exe set iDRAC.NIC.Selection 5")
	ret = Input_CMD_OS("racadm.exe get iDRAC.NIC.Selection")
	if(ret == False):
		return False
		
	for i in ret:
		if("LOM4" in i):
			flag_lom4 = True
	
	os.chdir(ROOT_DIR)
	
	if(flag_dedicated and flag_lom1 and flag_lom2 and flag_lom3 and flag_lom4):
		Log("Check_BMC_NCSI Pass",FONT_GREEN)
		return True
		
	else:
		if(flag_dedicated == False):
			Log("Check_BMC_NCSI Fail (Dedicated)",FONT_RED)
		if(flag_lom1 == False):
			Log("Check_BMC_NCSI Fail (LOM1)",FONT_RED)
		if(flag_lom2 == False):
			Log("Check_BMC_NCSI Fail (LOM2)",FONT_RED)
		if(flag_lom3 == False):
			Log("Check_BMC_NCSI Fail (LOM3)",FONT_RED)
		if(flag_lom4 == False):
			Log("Check_BMC_NCSI Fail (LOM4)",FONT_RED)
		return False
#===============================================================================
def Check_TPM_Device():
	'''Check TPM Device'''

	flag = False

	os.chdir(RACADM_DIR)

	cmd = "racadm.exe get bios.syssecurity"
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False

	for i in ret:
		if("TpmInfo=" in i and "2.0-NTC" in i):
			flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("Check_TPM_Device Pass", FONT_GREEN)
		return True
	else:
		Log("Check_TPM_Device Fail", FONT_RED)
		return False
#===============================================================================
def Check_Intrusion_Device():
	'''Check Intrusion Device'''
	
	flag = False
	
	os.chdir(IPMITOOL_DIR)
	
	cmd = "ipmitool.exe -I wmi chassis status"
	ret = Input_CMD_OS(cmd)
	if(ret == False):
		return False
		
	for i in range(len(ret)):
		if("Chassis Intrusion" in ret[i] and "active" in ret[i]):
			flag = True
                 
	os.chdir(ROOT_DIR)
	
	if(flag):
		Log("Check_Intrusion_Device Pass", FONT_GREEN)
		return True
	else:
		Log("Check_Intrusion_Device Fail", FONT_RED)
		return False
#===============================================================================
def Check_Fan_Device():
	'''Check_Fan_Device'''

	os.chdir(IPMITOOL_DIR)
	
	errorlist = []
	location = {
	            'Fan1A':    0.000,
				'Fan1B':    0.000,
				'Fan2A':    0.000,
				'Fan2B':    0.000,
				'Fan3A':    0.000,
				'Fan3B':    0.000,
				'Fan4A':    0.000,
				'Fan4B':    0.000,
				'Fan5A':    0.000,
				'Fan5B':    0.000,
				'Fan6A':    0.000,
				'Fan6B':    0.000,
				}

	ret = Input_CMD_OS("ipmitool.exe -I wmi sensor")
	if(ret == False):
		return False
		
	for i in range(len(ret)):
		for Fankey in location:
			if(Fankey in ret[i]):
				Log(ret[i].strip('\n'), FONT_YELLOW)
				if('na' in ret[i].split('|')[1]):
					errorlist.append("{0} Fail - {1}".format(Fankey, ret[i].split('|')[1]))
				else:
					if("RPM" in ret[i].split('|')[2]):
						if(float(ret[i].split('|')[1].strip()) > location[Fankey]):
							pass
						else:
							errorlist.append("{0} Fail - {1:f} RPM".format(Fankey, float(ret[i].split('|')[1])))

	os.chdir(ROOT_DIR)
		
	if(len(errorlist) != 0):
		print(errorlist)
		Log("Check_Fan_Device Fail", FONT_RED)
		return False
	
	Log("Check_Fan_Device PASS", FONT_GREEN)
	return True
#===============================================================================
def Check_BMC_SEL():
	'''Check BMC SEL for Critical Event'''

	flag = True

	os.chdir(RACADM_DIR)

	ret = Input_CMD_OS("racadm.exe getsel")
	if(ret == False):
		return False

	for i in ret:
		if("Severity:    Critical" in i):
			Log("Critical Error!! ==> %s"%(i), FONT_RED)
			flag = False

	os.chdir(ROOT_DIR)

	if(flag):
		Log("Check_BMC_SEL Pass", FONT_GREEN)
		return True
	else:
		Log("Check_BMC_SEL Fail", FONT_RED)
		return False
#===============================================================================
def Clear_BMC_SEL():
	'''Clear BMC SEL via ipmitool'''

	global IPMITOOL_DIR
	global ROOT_DIR

	flag = False

	os.chdir(IPMITOOL_DIR)

	ret = Input_CMD_OS("ipmitool.exe -I wmi sel clear")
	if(ret == False):
		return False

	ret = Input_CMD_OS("ipmitool.exe -I wmi sel")
	if(ret == False):
		return False

	for i in ret:
		if("Entries" in i):
			if(int(i.split()[2]) == 1):
				flag = True

	os.chdir(ROOT_DIR)

	if(flag):
		Log("Clear_BMC_SEL Pass", FONT_GREEN)
		return True
	else:
		Log("Clear_BMC_SEL Fail", FONT_RED)
		return False
#===============================================================================
def Set_AssetTag():
	'''Set Asset Tag to PASS:12345 via racadm'''

	global PYTHON27_DIR
	global ROOT_DIR

	flag = True

	os.chdir(PYTHON27_DIR)

    if(os.path.isfile("temp.dat") == True):
	    os.remove("temp.dat")
		
	ret = Input_CMD_OS("python.exe Medusa\medusa.py -d BIOS.Setup.1-1 -s AssetTag=PASS:12345 -k > .\\temp.dat")
	if(ret == False):
		flag = False
	
	#os.chdir(ROOT_DIR)
	ret = Input_CMD_OS("find \"AssetTag=PASS:12345\" .\\temp.dat")
	if(ret == False):
		flag = False
		
	Log("Asset has been SET PASS", FONT_GREEN)
	
	#os.chdir(PYTHON27_DIR)	
	ret = Input_CMD_OS("python.exe Medusa\medusa.py -d BIOS.InternalSetup.1-1 -s ServiceTag= -k > .\\temp.dat")
	if(ret == False):
		flag = False
		
	#os.chdir(ROOT_DIR)
	ret = Input_CMD_OS("find \"Set Attribute: ServiceTag=\" .\\temp.dat")
	if(ret == False):
		flag = False
		
	Log("Service Tag has been Deleted PASS", FONT_GREEN)
	
	'''
	os.chdir(RACADM_DIR)

	ret = Input_CMD_OS("racadm.exe set BIOS.MiscSettings.AssetTag PASS:12345")
	if(ret == False):
		return False

	ret = Input_CMD_OS("racadm.exe jobqueue create BIOS.Setup.1-1")
	if(ret == False):
		return False
		
	ret = Input_CMD_OS("racadm.exe get BIOS.MiscSettings.AssetTag")
	if(ret == False):
		return False
		
	for i in ret:
		if("AssetTag= (Pending Value=PASS:12345)" in i):
			flag = True
			
	os.chdir(ROOT_DIR)
	'''

	if(flag):
		Log("Set_AssetTag Pass", FONT_GREEN)
		return True
	else:
		Log("Set_AssetTag Fail", FONT_RED)
		return False
#===============================================================================
def main():
	global PPID
	global MACLIST
	global UUT_STATIONID
	global DEBUG_MODE
	global FAIL_CONTINUE
	global COM_PORT
	global LOG_DIR
	global LOG_FILE
	global BIOS_VER
	global CPLD_VER
	global BMC_VER
	global s

	VER = "0.1"

	Banner("Sitkall FVS Tool, By Foxconn CESBG-TEC-SW, Version: %s"%(VER))

	if(os.path.isdir(LOG_DIR) == False):
		os.mkdir(LOG_DIR)

	Scan_PPID()
	Scan_MAC()
	
	config = configparser.ConfigParser()
	config.read(os.path.join(SFC_DIR, "SFC.ini"))
	DEBUG_MODE = config.getboolean("Test", "DEBUG_MODE")
	FAIL_CONTINUE = config.getboolean("Test", "FAIL_CONTINUE")
	COM_PORT = config.get("Test", "COM_PORT")
	BIOS_VER = config.get("Test", "BIOS_VER")
	CPLD_VER = config.get("Test", "CPLD_VER")
	BMC_VER = config.get("Test", "BMC_VER")
	UUT_STATIONID = config.get("UUT", "stationid")
	config["UUT"]["diagsver"] = VER
	config["UUT"]["PPID"] = PPID
	config["UUT"]["result"] = "PASS"
	config["UUT"]["errormessage"] = "NA"
	config["UUT"]["biosver"] = "NA"
	config["UUT"]["firmwarever"] = "NA"
	config["UUT"]["begintime"] = "%d"%time.time()
	config.write(open(os.path.join(SFC_DIR, "SFC.ini"), "w"))

	try:
		s = serial.Serial(port=COM_PORT, baudrate = 115200, timeout = 1)
	except:
		Log("Open COM Port Fail!!", FONT_RED)
		sys.exit(-1)
		
	if(UUT_STATIONID == "DBG-001"):
		Log("DEBUG STATION", FONT_YELLOW)

	if(FAIL_CONTINUE):
		Log("Fail Continue!!", FONT_YELLOW)

	Log("Test Start...", FONT_YELLOW)

	test_sequence = [
		##Update_BMC_MAC,
		Check_BMC_MAC,
		Check_Ethernet_MAC,
		Check_Ethernet_Link,
		Check_Intrusion_Device,
		Check_Fan_Device,
		Check_FW_Version,
		Check_Memory_Info,
		##DDIAGS_Memory_Info
		Check_SMBIOS_Info,
		Program_MB_FRU,
		Check_CPU_Info,
		Check_Cache_Info,
		DDIAGS_Memory_Test,
		DDIAGS_PCIe_Test,
		Check_PCIe_Info_X4_1,
		Check_PCIe_Info_X4_2,
		Check_PCIe_Info_X8,
		Check_PCIe_Info_X16,
		Check_PCIe_Info_OCP,
		Check_PCIe_Info_Riser1,
		Check_PCH_Version,
		Check_HDD_Presence,
		Check_HDD_Info,
		DDIAGS_Disk_Test,
		##Check_BOSS_Info,
		Check_USB_Device,
		Check_USB3_Device,
		Check_Serial_Info,
		DDIAGS_Serial_Test,
		DDIAGS_Video_Test,
		##Check_BMC_NCSI,
		Check_BMC_Sensor,
		Check_TPM_Device,
		##Check_BMC_SEL,
		Clear_BMC_SEL,
		Set_AssetTag,
	]
	
	test_result = True
	result_msg = []

	for test_item in test_sequence:
		Banner(test_item.__doc__)
		Log("Test Item: %s (%s)"%(test_item.__doc__, test_item.__name__), FONT_YELLOW)
		if(test_item() == False):
			test_result = False
			result_msg.append((test_item.__name__, False))
			if(FAIL_CONTINUE):
				input("%s Fail!! Press Any Key to Continue..."%(test_item.__doc__))
			else:
				Show_Fail("%s Fail"%(test_item.__doc__))
				input("Press Any Key to Continue...")
				sys.exit(-1)
		else:
			result_msg.append((test_item.__name__, True))
		time.sleep(1)

	print("")
	for (item_name, result) in result_msg:
		temp = 57 - len(item_name) - 7
		if(result):
			msg = "%s "%(item_name) + "-"*temp + "[PASS]"
			Log(msg, FONT_GREEN)
		else:
			msg = "%s "%(item_name) + "-"*temp + "[FAIL]"
			Log(msg, FONT_RED)
	print("")

	if(FAIL_CONTINUE == False):
		Show_Pass()
		input("Press Any Key to Continue...")
	else:
		if(test_result):
			Log("Test Pass!!", FONT_GREEN)
			os.system("pause")
			sys.exit(0)
		else:
			Log("Test Fail!!", FONT_RED)
			os.system("pause")
			sys.exit(-1)
#===============================================================================
if(__name__ == "__main__"):
	main()
	sys.exit(0)
