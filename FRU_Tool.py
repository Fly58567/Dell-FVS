#===================================================================#
#       Tool Name: 14G FRU Tool                                     #
#         Version: 0.2                                              #
#         Edit by: Chris Liu 2016/07/13                             #
#===================================================================#
import sys
import datetime
import subprocess
import os
import argparse
import configparser
import time
import ctypes
import serial

global s

global DEBUG_MODE
DEBUG_MODE = True

global FRU_BIN

global ROOT_DIR
ROOT_DIR = os.getcwd()

global IPMITOOL_DIR
IPMITOOL_DIR = os.path.join(os.getcwd(), "ipmitool")

STD_OUTPUT_HANDLE = -11

FOREGROUND_BLACK     = 0x00
FOREGROUND_BLUE      = 0x01
FOREGROUND_GREEN     = 0x02
FOREGROUND_RED       = 0x04
FOREGROUND_INTENSITY = 0x08

FONT_WHITE = 0
FONT_RED   = 1
FONT_GREEN = 2
FONT_BLUE  = 3
FONT_YELLOW = 4

Card_Type_Dict = {
"Reserved":0x00,
"NDC":0x01,
"LOM":0x02,
"NIC":0x03,
"PERC (RAID supported)":0x04,
"Backplane":0x05,
"PSU":0x06,
"FC-HBA":0x07,
"Planar":0x08,
"IDSDM":0x09,
"Mezzanine":0x0A,
"SSD":0x0B,
"GPGPU":0x0C,
"PCIe SSD switch adapter":0x0D,
"PERC (Non-RAID only)":0x0E,
"Unidentified":0xFF
}
#==============================================================================
class Color:
	std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

	def set_cmd_color(self, color, handle=std_out_handle):
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
		self.set_cmd_color(FOREGROUND_BLUE | FOREGROUND_RED| FOREGROUND_INTENSITY)
		print(print_text)
		self.reset_color()
#===================================================================
def Banner(msg):
	line   = "#====================================================================#"
	line_1 = "#                                                                    #"

	x = int((len(line) - len(msg) - 2)/2)
	tmp_str = "#"

	for i in range(x):
		tmp_str = tmp_str + " "

	tmp_str = tmp_str + msg

	for i in range(x):
		tmp_str = tmp_str + " "

	if(len(msg)%2 == 0):
		tmp_str = tmp_str + "#"
	else:
		tmp_str = tmp_str + " #"

	clr = Color()
	clr.print_light_green_text("")
	clr.print_light_green_text(line)
	clr.print_light_green_text(line_1)
	clr.print_light_green_text(tmp_str)
	clr.print_light_green_text(line_1)
	clr.print_light_green_text(line)
	clr.print_light_green_text("")
#===============================================================================
def Log(string, index):
	global LOG_FILE

	now = datetime.datetime.today()
	tmp = "[%04d/%02d/%02d %02d:%02d:%02d] %s\n"%(now.year, now.month, now.day, now.hour, now.minute, now.second, string)

	f = open(LOG_FILE, "a")
	f.write(tmp)
	f.close()

	clr = Color()
	tmp = tmp.replace("\n", "")

	if(index == 1):
		clr.print_red_text(tmp)
	elif(index == 2):
		clr.print_green_text(tmp)
	elif(index == 3):
		clr.print_blue_text(tmp)
	elif(index == 4):
		clr.print_yellow_text(tmp)
	else:
		print(tmp)
#===============================================================================
def Find_Offset():
	Banner("Find FRU Offset!!")
	global DEBUG_MODE

	global FRU_BIN

	global Internal_Use_Area_Begin
	global Internal_Use_Area_End

	#global Board_Info_Area_Part_Number_Checksum_Index
	global Header_Checksum_Index
	global Feature_Flags_Index

	Internal_Use_Area_Begin = FRU_BIN[0x01] * 8
	Internal_Use_Area_End = Internal_Use_Area_Begin + FRU_BIN[Internal_Use_Area_Begin + 0x0D] - 1

	#Board_Info_Area_Part_Number_Checksum_Index = Internal_Use_Area_Begin + 0x05
	Header_Checksum_Index = Internal_Use_Area_Begin + 0x0E
	Feature_Flags_Index = Internal_Use_Area_Begin + 0x09

	global Board_Info_Area_Begin
	global Board_Info_Area_End

	global Mfg_Date_Time_Begin
	global Mfg_Date_Time_End

	global Board_Manufacturer_Type
	global Board_Manufacturer_Length
	global Board_Manufacturer_Begin
	global Board_Manufacturer_End

	global Board_Product_Name_Type
	global Board_Product_Name_Length
	global Board_Product_Name_Begin
	global Board_Product_Name_End

	global Board_Serial_Number_Type
	global Board_Serial_Number_Length
	global Board_Serial_Number_Begin
	global Board_Serial_Number_End

	global Board_Part_Number_Type
	global Board_Part_Number_Length
	global Board_Part_Number_Begin
	global Board_Part_Number_End

	global Board_Area_Checksum_Index
	global FRU_File_ID_Index

	Board_Info_Area_Begin = FRU_BIN[0x03] * 8
	Board_Info_Area_End = Board_Info_Area_Begin + FRU_BIN[Board_Info_Area_Begin + 1] * 8 - 1

	Mfg_Date_Time_Begin = Board_Info_Area_Begin + 3
	Mfg_Date_Time_End = Board_Info_Area_Begin + 5

	Board_Manufacturer_Type = Decode_Type(FRU_BIN[Mfg_Date_Time_End + 1])
	Board_Manufacturer_Length = FRU_BIN[Mfg_Date_Time_End + 1] & 0b00111111
	Board_Manufacturer_Begin = Mfg_Date_Time_End + 2
	Board_Manufacturer_End = Board_Manufacturer_Begin + Board_Manufacturer_Length - 1

	Board_Product_Name_Type = Decode_Type(FRU_BIN[Board_Manufacturer_End + 1])
	Board_Product_Name_Length = FRU_BIN[Board_Manufacturer_End + 1] & 0b00111111
	Board_Product_Name_Begin = Board_Manufacturer_End + 2
	Board_Product_Name_End = Board_Product_Name_Begin + Board_Product_Name_Length - 1

	Board_Serial_Number_Type = Decode_Type(FRU_BIN[Board_Product_Name_End + 1])
	Board_Serial_Number_Length = FRU_BIN[Board_Product_Name_End + 1] & 0b00111111
	Board_Serial_Number_Begin = Board_Product_Name_End + 2
	Board_Serial_Number_End = Board_Serial_Number_Begin + Board_Serial_Number_Length - 1

	Board_Part_Number_Type = Decode_Type(FRU_BIN[Board_Serial_Number_End + 1])
	Board_Part_Number_Length = FRU_BIN[Board_Serial_Number_End + 1] & 0b00111111
	Board_Part_Number_Begin = Board_Serial_Number_End + 2
	Board_Part_Number_End = Board_Part_Number_Begin + Board_Part_Number_Length - 1

	Board_Area_Checksum_Index = Board_Info_Area_End
	FRU_File_ID_Index = Board_Info_Area_Begin + 0x45

	if(DEBUG_MODE):
		Log("Checksum ==>", FONT_YELLOW)
		#Log("Board_Info_Area_Part_Number_Checksum(0x%02X) = 0x%02X (0x%02X ~ 0x%02X)"%(Board_Info_Area_Part_Number_Checksum_Index, FRU_BIN[Board_Info_Area_Part_Number_Checksum_Index], Board_Product_Name_Begin, Board_Product_Name_End), FONT_WHITE)
		Log("Header_Checksum(0x%02X) = 0x%02X (0x%02X ~ 0x%02X)"%(Header_Checksum_Index, FRU_BIN[Header_Checksum_Index], Internal_Use_Area_Begin, Internal_Use_Area_End), FONT_WHITE)
		Log("Board_Area_Checksum(0x%02X) = 0x%02X (0x%02X ~ 0x%02X)"%(Board_Area_Checksum_Index, FRU_BIN[Board_Area_Checksum_Index], Board_Info_Area_Begin, Board_Info_Area_End), FONT_WHITE)
		Log("Internal Use Area ==>", FONT_YELLOW)
		Log("Internal_Use_Area_Begin:0x%02X"%Internal_Use_Area_Begin, FONT_WHITE)
		Log("Internal_Use_Area_End:0x%02X"%Internal_Use_Area_End, FONT_WHITE)
		Log("Feature_Flags(0x%02X) = 0x%02X"%(Feature_Flags_Index, FRU_BIN[Feature_Flags_Index]), FONT_WHITE)
		Log("Board Info Area ==>", FONT_YELLOW)
		Log("Board_Info_Area_Begin:0x%02X"%Board_Info_Area_Begin, FONT_WHITE)
		Log("Board_Info_Area_End:0x%02X"%Board_Info_Area_End, FONT_WHITE)
		Log("Mfg_Date_Time_Begin:0x%02X"%Mfg_Date_Time_Begin, FONT_WHITE)
		Log("Mfg_Date_Time_End:0x%02X"%Mfg_Date_Time_End, FONT_WHITE)
		Log("Board_Manufacturer_Type:%s"%Board_Manufacturer_Type, FONT_WHITE)
		Log("Board_Manufacturer_Length:%d"%Board_Manufacturer_Length, FONT_WHITE)
		Log("Board_Manufacturer_Begin:0x%02X"%Board_Manufacturer_Begin, FONT_WHITE)
		Log("Board_Manufacturer_End:0x%02X"%Board_Manufacturer_End, FONT_WHITE)
		Log("Board_Product_Name_Type:%s"%Board_Product_Name_Type, FONT_WHITE)
		Log("Board_Product_Name_Length:%d"%Board_Product_Name_Length, FONT_WHITE)
		Log("Board_Product_Name_Begin:0x%02X"%Board_Product_Name_Begin, FONT_WHITE)
		Log("Board_Product_Name_End:0x%02X"%Board_Product_Name_End, FONT_WHITE)
		Log("Board_Serial_Number_Type:%s"%Board_Serial_Number_Type, FONT_WHITE)
		Log("Board_Serial_Number_Length:%d"%Board_Serial_Number_Length, FONT_WHITE)
		Log("Board_Serial_Number_Begin:0x%02X"%Board_Serial_Number_Begin, FONT_WHITE)
		Log("Board_Serial_Number_End:0x%02X"%Board_Serial_Number_End, FONT_WHITE)
		Log("Board_Part_Number_Type:%s"%Board_Part_Number_Type, FONT_WHITE)
		Log("Board_Part_Number_Length:%d"%Board_Part_Number_Length, FONT_WHITE)
		Log("Board_Part_Number_Begin:0x%02X"%Board_Part_Number_Begin, FONT_WHITE)
		Log("Board_Part_Number_End:0x%02X"%Board_Part_Number_End, FONT_WHITE)
		Log("FRU_File_ID(0x%02X) = 0x%02X"%(FRU_File_ID_Index, FRU_BIN[FRU_File_ID_Index]), FONT_WHITE)
#===============================================================================
def Find_Element():
	Banner("Find FRU Element!!")
	global DEBUG_MODE

	global FRU_BIN

	global Internal_Use_Area_Begin
	global Internal_Use_Area_End

	FRU_Size_B0 = FRU_BIN[Internal_Use_Area_Begin + 0x0B]
	FRU_Size_B1 = FRU_BIN[Internal_Use_Area_Begin + 0x0C]

	FRU_Size = (FRU_Size_B1 << 8) + FRU_Size_B0

	Log("FRU Size = %d Bytes"%(FRU_Size), FONT_YELLOW)

	Element_Count = FRU_BIN[Internal_Use_Area_Begin + 0x0F]

	Log("FRU Element Count = %d"%(Element_Count), FONT_YELLOW)

	for i in range(Element_Count):
		Element_Type = FRU_BIN[Internal_Use_Area_Begin + 0x10 + 3*i]
		Element_Offset_B0 = FRU_BIN[Internal_Use_Area_Begin + 0x10 + 3*i + 1]
		Element_Offset_B1 = FRU_BIN[Internal_Use_Area_Begin + 0x10 + 3*i + 2]
		Element_Offset = (Element_Offset_B1 << 8) + Element_Offset_B0
		Log("Find Element!! Type: 0x%02X, Offset: 0x%04X"%(Element_Type, Element_Offset), FONT_YELLOW)
		if(Element_Type == 0xD2):
			Element_D2(Element_Offset)
#===============================================================================
def Element_D2(offset):
	Banner("Element Type 0xD2: BMC Management Info")
	global FRU_BIN
	global CARD_TYPE

	Element_Type = FRU_BIN[offset]
	Element_Length = (FRU_BIN[offset + 2] << 8) + FRU_BIN[offset + 1]

	Log("Element Length = 0x%02X"%(Element_Length), FONT_YELLOW)

	if(Element_Type != 0xD2):
		Log("Element Type Error!!", FONT_RED)

	FRU_BIN[offset + 5] = Card_Type_Dict[CARD_TYPE]

	Log("Element Card Type[0x%02X] = 0x%02X"%(offset + 5 ,FRU_BIN[offset + 5]), FONT_YELLOW)

	checksum = 0
	for i in range(Element_Length):
		if(i != 3):
			checksum = checksum + FRU_BIN[offset + i]
	checksum = (~checksum+1)%256
	FRU_BIN[offset + 3] = checksum
	Log("Element Checksum[0x%02X] = 0x%02X"%(offset + 3 ,FRU_BIN[offset + 3]), FONT_YELLOW)
#===============================================================================
def Decode_Type(x):
	tmp = (x & 0b11000000) >> 6
	if(tmp == 0b00):
		return "Binary"
	elif(tmp == 0b01):
		return "BCD Plus"
	elif(tmp == 0b10):
		return "6BIT_ASCII"
	elif(tmp == 0b11):
		return "ASCII"
#===============================================================================
def Date_Code(x):
	if(x.isdigit() == True):
		return int(x)
	elif(x.isupper() == True):
		return ord(x) - 65 + 10
	else:
		return 0
#===============================================================================
def Compare_FRU():
	Banner("Compare FRU Data!!")
	global TEMP_BIN
	global FRU_BIN
	global TEMP_FILE
	global FRU_FILE

	global Mfg_Date_Time_Begin
	global Mfg_Date_Time_End
	global Board_Serial_Number_Begin
	global Board_Serial_Number_End
	global Board_Part_Number_Begin
	global Board_Part_Number_End

	#global Board_Info_Area_Part_Number_Checksum_Index
	global Header_Checksum_Index
	global Board_Area_Checksum_Index

	global Feature_Flags_Index


	Log("Template FRU File: %s"%(TEMP_FILE), FONT_YELLOW)
	Log("Compare  FRU File: %s"%(FRU_FILE), FONT_YELLOW)


	SKIP = []
	FAIL = []

	#Manufacturing Date/Time(0x0B ~ 0x0D). Minutes from 1996/1/1. LSB First.
	for i in range(Mfg_Date_Time_Begin, Mfg_Date_Time_End + 1):
		SKIP.append(i)

	#Board Serial Number. PPID: Country, MFG ID, Date Code, Serial Number.
	for i in range(Board_Serial_Number_Begin, Board_Serial_Number_End + 1):
		SKIP.append(i)

	#Board Part Number. PWA Part Number & Revision
	for i in range(Board_Part_Number_Begin, Board_Part_Number_End + 1):
		SKIP.append(i)

	#Board Area Checksum
		SKIP.append(Board_Area_Checksum_Index)

	#Board Info Area Part Number Checksum
		#SKIP.append(Board_Info_Area_Part_Number_Checksum_Index)

	#Header Checksum
		SKIP.append(Header_Checksum_Index)

	#Feature Flags
		SKIP.append(Feature_Flags_Index)

	result = True
	for i in range(len(FRU_BIN)):
		if((i not in SKIP) and (FRU_BIN[i] != TEMP_BIN[i])):
			FAIL.append(i)
			result = False

	if(result == True):
		Log("Compare FRU Pass!!", FONT_GREEN)
	else:
		Log("Compare FRU Fail!!", FONT_RED)
		for i in FAIL:
			Log("    Location:0x%02X. Template:0x%02X, Input:0x%02X."%(i, TEMP_BIN[i], FRU_BIN[i]), FONT_RED)
#===============================================================================
def Program_MFG_Time():
	Banner("Program Manufacture Date/Time!!")
	global FRU_BIN

	global Mfg_Date_Time_Begin

	Mfg_Date_Time_B0 = Mfg_Date_Time_Begin
	Mfg_Date_Time_B1 = Mfg_Date_Time_Begin + 1
	Mfg_Date_Time_B2 = Mfg_Date_Time_Begin + 2

	Base_Time = datetime.datetime(1996, 1, 1, 0, 0)
	System_Time = datetime.datetime.now()
	Delta_Minutes = int((System_Time - Base_Time).total_seconds()/60)

	FRU_BIN[Mfg_Date_Time_B0] = (Delta_Minutes & 0x0000FF)
	FRU_BIN[Mfg_Date_Time_B1] = (Delta_Minutes & 0x00FF00) >> 8
	FRU_BIN[Mfg_Date_Time_B2] = (Delta_Minutes & 0xFF0000) >> 16

	Log("Mfg_Date_Time_B0 (0x%02X) = 0x%02X"%(Mfg_Date_Time_B0, FRU_BIN[Mfg_Date_Time_B0]), FONT_YELLOW)
	Log("Mfg_Date_Time_B1 (0x%02X) = 0x%02X"%(Mfg_Date_Time_B1, FRU_BIN[Mfg_Date_Time_B1]), FONT_YELLOW)
	Log("Mfg_Date_Time_B2 (0x%02X) = 0x%02X"%(Mfg_Date_Time_B2, FRU_BIN[Mfg_Date_Time_B2]), FONT_YELLOW)
#===============================================================================
def Check_MFG_Time():
	Banner("Check Manufacture Date/Time!!")
	global FRU_BIN
	global MAX_DATE

	global Mfg_Date_Time_Begin
	global Mfg_Date_Time_End

	tmp = 0
	for i in range(Mfg_Date_Time_End, Mfg_Date_Time_Begin - 1, -1):
		tmp = tmp + FRU_BIN[i]
		if(i != Mfg_Date_Time_Begin):
			tmp = tmp << 8

	Base_Time = datetime.datetime(1996, 1, 1, 0, 0)
	System_Time = datetime.datetime.now()
	Delta_Time = datetime.timedelta(minutes = tmp)
	Manufacture_Time = Base_Time + Delta_Time
	Log("Manufacturing Date/Time (0x%02X ~ 0x%02X): %04d/%02d/%02d %02d:%02d"%(Mfg_Date_Time_Begin, Mfg_Date_Time_End, Manufacture_Time.year,Manufacture_Time.month,Manufacture_Time.day,Manufacture_Time.hour,Manufacture_Time.minute), FONT_YELLOW)

	if(Manufacture_Time > System_Time - datetime.timedelta(days = MAX_DATE)):
		Log("FRU Time Check (Less than %dDay): Pass!!"%(MAX_DATE), FONT_GREEN)
	else:
		Log("FRU Time Check (Less than %dDay): Fail"%(MAX_DATE), FONT_RED)
#===============================================================================
def Program_PPID(PPID):
	Banner("Program FRU PPID!!")
	global Board_Product_Name_Type
	global Board_Product_Name_Begin
	global Board_Product_Name_End

	global Board_Serial_Number_Type
	global Board_Serial_Number_Begin
	global Board_Serial_Number_End

	FRU_PN = PPID[2:8] + PPID[20:]
	FRU_SN = PPID[0:2] + PPID[8:20]

	FRU_BIN[Board_Part_Number_Begin:Board_Part_Number_End + 1] = bytes(FRU_PN,'ascii')
	FRU_BIN[Board_Serial_Number_Begin:Board_Serial_Number_End + 1] = bytes(FRU_SN,'ascii')

	Log("Board_Part_Number (0x%02X ~ 0x%02X): %s"%(Board_Part_Number_Begin, Board_Part_Number_End, FRU_BIN[Board_Part_Number_Begin:Board_Part_Number_End + 1].decode(Board_Part_Number_Type)), FONT_YELLOW)
	Log("Board_Serial_Number (0x%02X ~ 0x%02X): %s"%(Board_Serial_Number_Begin, Board_Serial_Number_End, FRU_BIN[Board_Serial_Number_Begin:Board_Serial_Number_End + 1].decode(Board_Serial_Number_Type)), FONT_YELLOW)

	#After Program PPID
	FRU_BIN[Feature_Flags_Index] = 0x02
	#FRU_BIN[FRU_File_ID_Index] = 0x06

	if(PPID[2:8] == "0PFRMT"):
		Product_Name = "PowerEdge X640"
		Log("Program Product Name \"%s\" into FRU"%(Product_Name), FONT_YELLOW)
		FRU_BIN[Board_Product_Name_Begin:Board_Product_Name_Begin + len(Product_Name)] = bytes(Product_Name,'ascii')
	elif(PPID[2:8] == "0PFRMT"):
		Product_Name = "PowerEdge X840"
		Log("Program Product Name \"%s\" into FRU"%(Product_Name), FONT_YELLOW)
		FRU_BIN[Board_Product_Name_Begin:Board_Product_Name_Begin + len(Product_Name)] = bytes(Product_Name,'ascii')
#===============================================================================
def Check_PPID(PPID):
	Banner("Check FRU PPID!!")
	global Board_Manufacturer_Type
	global Board_Manufacturer_Length
	global Board_Manufacturer_Begin
	global Board_Manufacturer_End

	global Board_Product_Name_Type
	global Board_Product_Name_Begin
	global Board_Product_Name_End

	global Board_Serial_Number_Type
	global Board_Serial_Number_Begin
	global Board_Serial_Number_End

	global Board_Part_Number_Type
	global Board_Part_Number_Begin
	global Board_Part_Number_End

	global CARD_TYPE

	if(FRU_BIN[Board_Manufacturer_Begin:Board_Manufacturer_End + 1] == b'd\xc9\xb2'):
		Manufacture_Name = "DELL"

	FRU_SN = PPID[0:2] + PPID[8:20]
	FRU_PN = PPID[2:8] + PPID[20:]

	Product_Name = FRU_BIN[Board_Product_Name_Begin:Board_Product_Name_End + 1].decode(Board_Product_Name_Type)
	SN = FRU_BIN[Board_Serial_Number_Begin:Board_Serial_Number_End + 1].decode(Board_Serial_Number_Type)
	PN = FRU_BIN[Board_Part_Number_Begin:Board_Part_Number_End + 1].decode(Board_Part_Number_Type)
	PPID = SN[0:2] + PN[0:6] + SN[2:] + PN[6:]
	DPN = PPID[2:8]

	Log("Board Manufacture Name (0x%02X ~ 0x%02X): %s"%(Board_Manufacturer_Begin,Board_Manufacturer_End,Manufacture_Name), FONT_WHITE)
	Log("Board Product Name (0x%02X ~ 0x%02X): %s"%(Board_Product_Name_Begin,Board_Product_Name_End,Product_Name), FONT_WHITE)
	Log("Board Serial Number (0x%02X ~ 0x%02X): %s"%(Board_Serial_Number_Begin,Board_Serial_Number_End,SN), FONT_WHITE)
	Log("Board Part Number (0x%02X ~ 0x%02X): %s"%(Board_Part_Number_Begin,Board_Part_Number_End,PN), FONT_WHITE)
	Log("Board PPID: %s"%(PPID), FONT_WHITE)
	Log("    Country: %s"%(PPID[0:2]), FONT_WHITE)
	Log("    Dell P/N: %s (%s)"%(DPN, CARD_TYPE), FONT_WHITE)
	Log("    Mfg. ID: %s"%(PPID[8:13]), FONT_WHITE)
	Log("    Date: %s (201%d/%02d/%02d)"%(PPID[13:16],Date_Code(PPID[13]),Date_Code(PPID[14]),Date_Code(PPID[15])), FONT_WHITE)
	Log("    S/N: %s"%(PPID[16:20]), FONT_WHITE)
	Log("    Revision: %s"%(PPID[20:]), FONT_WHITE)
#===============================================================================
def Program_Checksum():
	Banner("Program FRU Checksum!!")
	global FRU_BIN

	#global Board_Info_Area_Part_Number_Checksum_Index
	global Header_Checksum_Index
	global Board_Area_Checksum_Index

	global Internal_Use_Area_Begin
	global Internal_Use_Area_End
	global Board_Info_Area_Begin
	global Board_Info_Area_End
	#global Board_Part_Number_Begin
	#global Board_Part_Number_End

	#Board_Info_Area_Part_Number_Checksum = 0
	Header_Checksum = 0
	Board_Area_Checksum = 0

	'''for i in range(Board_Part_Number_Begin, Board_Part_Number_End + 1):
		Board_Info_Area_Part_Number_Checksum = Board_Info_Area_Part_Number_Checksum + FRU_BIN[i]
	Board_Info_Area_Part_Number_Checksum = (~Board_Info_Area_Part_Number_Checksum+1)%256
	FRU_BIN[Board_Info_Area_Part_Number_Checksum_Index] = Board_Info_Area_Part_Number_Checksum'''

	for i in range(Internal_Use_Area_Begin, Internal_Use_Area_End):
		if(i != Header_Checksum_Index):
			Header_Checksum = Header_Checksum + FRU_BIN[i]
	Header_Checksum = (~Header_Checksum+1)%256
	FRU_BIN[Header_Checksum_Index] = Header_Checksum

	for i in range(Board_Info_Area_Begin, Board_Info_Area_End):
		if(i != Board_Area_Checksum_Index):
			Board_Area_Checksum = Board_Area_Checksum + FRU_BIN[i]
	Board_Area_Checksum = (~Board_Area_Checksum+1)%256
	FRU_BIN[Board_Area_Checksum_Index] = Board_Area_Checksum

	#Log("Board_Info_Area_Part_Number_Checksum (0x%02X) = 0x%02X"%(Board_Info_Area_Part_Number_Checksum_Index, Board_Info_Area_Part_Number_Checksum), FONT_YELLOW)
	Log("Header_Checksum (0x%02X) = 0x%02X"%(Header_Checksum_Index, Header_Checksum), FONT_YELLOW)
	Log("Board_Area_Checksum (0x%02X) = 0x%02X"%(Board_Area_Checksum_Index, Board_Area_Checksum), FONT_YELLOW)
#===============================================================================
def Check_Checksum():
	Banner("Check FRU Checksum!!")
	global FRU_BIN

	#global Board_Info_Area_Part_Number_Checksum_Index
	global Header_Checksum_Index
	global Board_Area_Checksum_Index

	global Internal_Use_Area_Begin
	global Internal_Use_Area_End
	global Board_Info_Area_Begin
	global Board_Info_Area_End
	#global Board_Part_Number_Begin
	#global Board_Part_Number_End

	#checksum1_result = False
	checksum2_result = False
	checksum3_result = False

	#checksum1 = 0
	checksum2 = 0
	checksum3 = 0

	#Board Info Area Part Number Checksum
	'''for i in range(Board_Part_Number_Begin, Board_Part_Number_End + 1):
		checksum1 = checksum1 + FRU_BIN[i]
	checksum1 = checksum1 + FRU_BIN[Board_Info_Area_Part_Number_Checksum_Index]
	if(checksum1%256 == 0):
		checksum1_result = True
	if(checksum1_result == False):
		temp1 = checksum1 - FRU_BIN[Board_Info_Area_Part_Number_Checksum_Index]
		checksum1 = (~temp1 + 1)%256'''

	#Header Checksum
	for i in range(Internal_Use_Area_Begin, Internal_Use_Area_End + 1):
		checksum2 = checksum2 + FRU_BIN[i]
	if(checksum2%256 == 0):
		checksum2_result = True
	if(checksum2_result == False):
		temp2 = checksum2 - FRU_BIN[Header_Checksum_Index]
		checksum2 = (~temp2 + 1)%256

	#Board Area Checksum
	for i in range(Board_Info_Area_Begin, Board_Info_Area_End + 1):
		checksum3 = checksum3 + FRU_BIN[i]
	if(checksum3%256 == 0):
		checksum3_result = True
	if(checksum3_result == False):
		temp3 = checksum3 - FRU_BIN[Board_Area_Checksum_Index]
		checksum3 = (~temp3 + 1)%256

	if(checksum1_result == True):
		Log("Board_Info_Area_Part_Number_Checksum (0x%02X): PASS"%Board_Info_Area_Part_Number_Checksum_Index, FONT_GREEN)
	else:
		Log("Board_Info_Area_Part_Number_Checksum (0x%02X): FAIL"%Board_Info_Area_Part_Number_Checksum_Index, FONT_RED)
		Log("Correct Checksum:0x%02X"%checksum1, FONT_RED)

	if(checksum2_result == True):
		Log("Header_Checksum (0x%02X): PASS"%Header_Checksum_Index, FONT_GREEN)
	else:
		Log("Header_Checksum (0x%02X): FAIL"%Header_Checksum_Index, FONT_RED)
		Log("Correct Checksum:0x%02X"%checksum2, FONT_RED)

	if(checksum3_result == True):
		Log("Board_Area_Checksum (0x%02X): PASS"%Board_Area_Checksum_Index, FONT_GREEN)
	else:
		Log("Board_Area_Checksum (0x%02X): FAIL"%Board_Area_Checksum_Index, FONT_RED)
		Log("Correct Checksum:0x%02X"%checksum3, FONT_RED)
#===============================================================================
def Read_Write_FRU():
	global FRU_ID
	global FRU_BIN
	global IPMITOOL_DIR

	os.chdir("IPMITOOL_DIR")

	OLD_FRU = "old_fru.bin"
	NEW_FRU = "new_fru.bin"

	Log("Read FRU to %s!!"%OLD_FRU, FONT_WHITE)
	cmd = "ipmitool -I wmi fru read %d %s"%(FRU_ID, OLD_FRU)
	ret = subprocess.check_output(cmd, timeout = 10)
	if(b'Done' in ret):
		Log("Read FRU Pass!!", FONT_GREEN)
	else:
		Log("Read FRU Fail!!", FONT_RED)

	f1 = open(OLD_FRU,"rb")
	FRU_BIN = bytearray(f1.read())
	f1.close()

	f2 = open(NEW_FRU,"wb")
	f2.write(FRU_BIN)
	f2.close()

	Log("Write FRU from %s!!"%NEW_FRU, FONT_WHITE)
	cmd = "ipmitool -I wmi fru write %d %s"%(FRU_ID, NEW_FRU)
	ret = subprocess.check_output(cmd, timeout = 10)
	if(b'Done' in ret):
		Log("Write FRU Pass!!", FONT_GREEN)
	else:
		Log("Write FRU Fail!!", FONT_RED)

	os.chdir("ROOT_DIR")
#===============================================================================
def Input_iDRAC_CMD(cmd):
	global s

	Log("Input Command: %s"%(cmd), FONT_YELLOW)

	cmd = "%s\r"%(cmd)

	s.write(cmd.encode())
	ret = s.readlines()
	for i in range(len(ret)):
		ret[i] = ret[i].decode().strip()
		Log("ret[%d] %s"%(i, ret[i]), FONT_WHITE)

	#time.sleep(0.5)

	return ret
#===============================================================================
def Enter_iDRAC_Kernel():
	Banner("Login iDRAC Kernel")
	print("Waiting for login iDRAC kernel!!")
	'''timeout_5s = 1
	for i in range(timeout_5s):
		print(("%s secs...")%(5*(timeout_5s - i)))
		time.sleep(5)'''

	for i in range(10):
		ret = Input_iDRAC_CMD("pwd")
		if("/home/root#" in ret[2]):
			Log("Enter iDRAC Linux Kernel", FONT_YELLOW)
			break

		if(i != 9):
			time.sleep(10)
			print(("%s secs...")%(10*(10 - i)))
		else:
			Log("Enter iDRAC Linux Kernel Fail (TIMEOUT!!)", FONT_RED)
			return False

	Log("Enter iDRAC Linux Kernel Pass", FONT_GREEN)
	return True
#===============================================================================
def Write_FRU():
	#Write FRU via iDRAC Kernel (libi2ctest)
	global FRU_BIN
	global CARD_TYPE

	if(CARD_TYPE == "Planar"):
		i2c_bus = 5
		i2c_addr = 0xA0
	elif(CARD_TYPE == "Backplane"):
		i2c_bus = 4
		i2c_addr = 0xAA
	else:
		i2c_bus = 5
		i2c_addr = 0xA0

	for i in range(16):
		payload = "0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X"%(
			FRU_BIN[i*16], FRU_BIN[i*16 + 1], FRU_BIN[i*16 + 2], FRU_BIN[i*16 + 3],
			FRU_BIN[i*16 + 4], FRU_BIN[i*16 + 5], FRU_BIN[i*16 + 6], FRU_BIN[i*16 + 7],
			FRU_BIN[i*16 + 8], FRU_BIN[i*16 + 9], FRU_BIN[i*16 + 10], FRU_BIN[i*16 + 11],
			FRU_BIN[i*16 + 12], FRU_BIN[i*16 + 13], FRU_BIN[i*16 + 14], FRU_BIN[i*16 + 15])
		write_cmd = "libi2ctest -c %d 100 100 3 -a 0x%02X -m 0 17 0x%02X %s 0"%(i2c_bus, i2c_addr, i*16, payload)
		read_cmd  = "libi2ctest -c %d 100 100 3 -a 0x%02X -m 0 1 0x%02X 16"%(i2c_bus, i2c_addr, i*16)
		ret = Input_iDRAC_CMD(write_cmd)
		#ret = Input_iDRAC_CMD(read_cmd)
		#if(ret[9] == payload):
		if("Write Done!" in ret[-2]):
			Log("Program FRU Offset[0x%02X] PASS!!"%(i*16), FONT_GREEN)
		else:
			Log("Program FRU Offset[0x%02X] PASS!!"%(i*16), FONT_RED)
			return False
			
	return True
#===============================================================================
def main(argv):
	global LOG_FILE
	global TEMP_FILE
	global FRU_BIN
	global TEMP_BIN
	global PPID
	global COM_PORT
	global CARD_TYPE
	global s

	VER = "0.2"

	now = datetime.datetime.today()
	LOG_FILE = "Log_FRU_Tool_%02d%02d-%02d%02d.txt"%(now.month, now.day, now.hour, now.minute)

	Banner("14G FRU Tool, By Foxconn CESBG-TEC-SW, Version: %s"%(VER))

	opts = argparse.ArgumentParser(description = "14G FRU Tool, By Foxconn CESBG-TEC-SW, Version: %s"%(VER))
	opts.add_argument('-v', '--version', action = 'version', version = VER, help = "Show Tool Version")
	#opts.add_argument('-s', '--show', action = "store_true", required = False, help = "Show PPID")
	#opts.add_argument('-c', '--check', action = "store_true", required = False, help = "Check G5 MC/BC/IM FW Version")
	#opts.add_argument('-u', '--update', action = "store_true", required = False, help = "Update G5 MC/BC/IM FW")
	opts.add_argument('-p', '--ppid', required = True, default = "CN0PFRMT779216AS0004X02", help = "Update FRU with PPID")
	opts.add_argument('-c', '--com', required = True, default = "COM3", help = "COM Port")

	args = opts.parse_args()

	try:
		s = serial.Serial(port=args.com, baudrate = 115200, timeout = 1)
	except:
		Log("Open COM Port Fail!!", FONT_RED)
		sys.exit(-1)
	

	if(len(args.ppid) != 23 or args.ppid[0:2] != "CN" or args.ppid[8:13] != "77921"):
		Log("Wrong PPID!! (%s)"%(args.ppid), FONT_RED)
		sys.exit(-1)

	PPID = args.ppid
	
	Log("PPID = %s"%(PPID), FONT_YELLOW)

	if(Enter_iDRAC_Kernel() == False):
		Log("Enter_iDRAC_Kernel Fail", FONT_RED)
		sys.exit(-1)
	if(PPID[2:8] == "0177V9"):
		Log("Board: Pathfinder Planar", FONT_YELLOW)
		CARD_TYPE = "Planar"
		FRU_FILE = "14G_Planar_X04_512B.bin"
		FRU_BIN = bytearray(512)
	elif(PPID[2:8] == "0FWRNY"):
		Log("Board: Pathfinder BPx6", FONT_YELLOW)
		CARD_TYPE = "Backplane"
		FRU_FILE = "14G_BP_X04_256B.bin"
		FRU_BIN = bytearray(256)
	elif(PPID[2:8] == "0740HW"):
		Log("Board: Sojourner Planar", FONT_YELLOW)
		CARD_TYPE = "Planar"
		FRU_FILE = "14G_Planar_X02_512B.bin"
		FRU_BIN = bytearray(512)
	elif(PPID[2:8] == "06NGJK"):
		Log("Board: Sojourner Backplane", FONT_YELLOW)
		CARD_TYPE = "Backplane"
		FRU_FILE = "14G_BP_X04_256B.bin"
		FRU_BIN = bytearray(256)
	else:
		Log("Unknown PPID", FONT_RED)
		sys.exit(-1)

	#f = open(FRU_FILE,"rb")
	#FRU_BIN = bytearray(f.read())
	#f.close()

	try:
		f = open(FRU_FILE,"rb")
		FRU_BIN = bytearray(f.read())
		f.close()
	except:
		Log("Open FRU File Fail (%s)"%(FRU_FILE), FONT_RED)
		sys.exit(-1)

	Find_Offset()
	Find_Element()
	#Compare_FRU()

	#Check_MFG_Time()
	#Check_PPID(PPID)
	#Check_Checksum()

	Program_MFG_Time()
	Program_PPID(PPID)
	Program_Checksum()

	if(Write_FRU() == False):
		Log("Write_FRU Fail", FONT_RED)
		sys.exit(-1)

	Banner("DONE")
	BIN_FILE = "FRU_%s_%02d%02d-%02d%02d.bin"%(PPID, now.month, now.day, now.hour, now.minute)
	f = open(BIN_FILE,"wb")
	f.write(FRU_BIN)
	f.close()
	Log("Write FRU Back (%s)"%(BIN_FILE), FONT_YELLOW)
	s.close()
#===============================================================================
if __name__ == '__main__':
	main(sys.argv)
	sys.exit(0)

