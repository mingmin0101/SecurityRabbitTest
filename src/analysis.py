import os
import pefile
import peutils
import wmi
import subprocess
import platform
import time
import win32api
import string
import math
from settings import baseDir,dataDir,confDir

# TOP LEVEL
def host_info(hostInfo_checked, registry_checked):
    """
    1. 取得掃描端點之硬體、軟體及作業系統資訊(wmi)
    2. 判斷檔案是否註冊於windows系統機碼，開機可自動啟動(wmi) 
    """
    w = wmi.WMI()
    host_info_dict = {}
    
    if(hostInfo_checked):
        x = subprocess.check_output('wmic csproduct get UUID')
        host_info_dict['deviceUUID']= x.decode("utf-8").replace('UUID','').replace('\n','').replace('\r','').replace(' ','')
        host_info_dict['deviceName'] = platform.node()
        host_info_dict['os'] = "{}-{}".format(platform.system(),platform.version())
        host_info_dict['processor'] = platform.processor()
        host_info_dict['cpu'] = platform.machine()
        host_info_dict['userName'] = os.getlogin()
        
        totalSize = 0
        for memModule in w.Win32_PhysicalMemory():
            totalSize += int(memModule.Capacity)
        host_info_dict['memoryCapacity'] = totalSize/1048576
    
    if(registry_checked):
        registry_list = []
        for s in w.Win32_StartupCommand(): 
            registry_list.append((s.Location, s.Caption, s.Command))
        host_info_dict['registry_list'] = registry_list
    return host_info_dict

# TOP LEVEL
def pefile_dump(filepath):
    filename = os.path.join(dataDir,'pefileInfo.txt')
    fileIndex = os.path.join(dataDir,'pefileIndex.txt')
    pe = pefile.PE(filepath, fast_load=True)

    start = 0
    end = 0
    with open(filename,'a') as f:
        start = f.tell()
        f.write(pe.dump_info())
        end = f.tell()
    with open(fileIndex,'a') as i:
        i.write("{} {} {} \n".format(filepath,start,end))
    
    return "file stored at {}".format(dataDir)

# TOP LEVEL
def file_info(filepath):
    created = time.ctime(os.path.getctime(filepath))   # create time
    last_modified = time.ctime(os.path.getmtime(filepath))   # modified time
    last_accessed = time.ctime(os.path.getatime(filepath))   # access time
    file_size = os.stat(filepath).st_size
    file_attribute = win32api.GetFileAttributes(filepath)
    file_info_dict = {
        'file_name':filepath,
        'file_size':file_size,
        'file_attribute':file_attribute,
        'created':created,
        'last_modified':last_modified,
        'last_accessed':last_accessed
    }
    # BYTEWISE ANALYSIS
    byte_analysis_dict = byte_analysis(filepath)

    # PE_FILE ANALYSIS
    pe_file = pefile.PE(filepath, fast_load=True)
    check_pack_dict = check_pack(pe_file)
    dll_import_analysis_dict = dll_import_analysis(pe_file)

    file_info_dict.update(byte_analysis_dict)
    file_info_dict.update(check_pack_dict)
    file_info_dict.update(dll_import_analysis_dict)
    return file_info_dict

#加殼
def check_pack(pe_file):
    signature_file = os.path.join(confDir,'userdb_filter.txt')
    signatures = None
    with open(signature_file,'r',encoding='utf-8') as f:
        sig_data = f.read()
        signatures = peutils.SignatureDatabase(data = sig_data)

    #matches = signatures.match(pe_file, ep_only = True)
    matchall = signatures.match_all(pe_file, ep_only = True)
    if not matchall:
        matchall = []
    return { 'pack' : matchall }

def dll_import_analysis(pe_file):
    NETWORKING_AND_INTERNET_DLLS = ['dnsapi.dll', 'dhcpcsvc.dll', 'dhcpcsvc6.dll', 'dhcpsapi.dll', 'connect.dll', 
                           'httpapi.dll', 'netshell.dll', 'iphlpapi.dll', 'netfwv6.dll', 'dhcpcsvc.dll',
                           'hnetcfg.dll', 'netapi32.dll', 'qosname.dll', 'rpcrt4.dll', 'mgmtapi.dll', 'snmpapi.dll',
                           'smbwmiv2.dll', 'tapi32.dll', 'netapi32.dll', 'davclnt.dll', 'websocket.dll',
                           'bthprops.dll', 'wifidisplay.dll', 'wlanapi.dll', 'wcmapi.dll', 'fwpuclnt.dll',
                           'firewallapi.dll', 'winhttp.dll', 'wininet.dll', 'wnvapi.dll', 'ws2_32.dll',
                           'webservices.dll']
    FILE_MANAGEMENT_DLLS = ['advapi32.dll', 'kernel32.dll', 'wofutil.dll', 'lz32.dll']
    EXECUTION_FUNCTIONS = ['winexec']

    network_ability = []
    rw_ability = []
    exec_ability = []

    pe_file.parse_data_directories()
    for entry in pe_file.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('utf-8').lower()
        # check if there is a matching dll import
        if dll in NETWORKING_AND_INTERNET_DLLS:
            network_ability.append(dll)
        if dll in FILE_MANAGEMENT_DLLS:
            rw_ability.append(dll)
        
        for imp in entry.imports:
            # check if there is a matching function import
            if imp in EXECUTION_FUNCTIONS:
                exec_ability.append((hex(imp.address),imp.name.decode('utf-8')))
        dll_analysis_dict = {
            'network_ability' : network_ability,
            'rw_ability' : rw_ability,
            'exec_ability' : exec_ability
        }
    return dll_analysis_dict

def byte_analysis(filepath):
    chunk_size = 8192
    printable_chars = set(bytes(string.printable,'ascii'))
    printable_str_list = []
    byte_list = [0] * 256

    with open(filepath,'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            __one_gram_byte_summary(chunk, byte_list)
            __byte_printable(chunk, printable_chars, printable_str_list)
    entropy = __entropy(byte_list)
            
    byte_analysis_dict = {
        'printable_strs' : printable_str_list,
        'byte_summary' : byte_list,
        'entropy' : entropy
    }
    return byte_analysis_dict


def __one_gram_byte_summary(chunk,byteList):
    for byte in chunk:
        byteList[byte] +=1
    return byteList
        
def __entropy(byteList):
    entropy = 0
    total = 0
    for byte_count in byteList:
        total += byte_count

    for byte_count in byteList:
        if byte_count == 0:
            continue
        p = 1.0 * byte_count/total
        entropy -= math.log(p, 2)
    return entropy

def __byte_printable(chunk,printable_chars,printable_str_list):
    temp_bytes = b""
    for byte in chunk:
        if byte in printable_chars:
            temp_bytes += bytes([byte])
        
        elif not temp_bytes == b"\x00" and len(temp_bytes) > 2:
            printable_str_list.append(temp_bytes.decode("ascii"))
            temp_bytes = b""
        else:
            temp_bytes = b""
    return printable_str_list

if __name__ == '__main__':
    t1 = "C:/Users/user/AppData/Local/LINE/bin/LineLauncher.exe"
    t2 = "D:/ProgramFiles/AVAST Software/Avast/defs/19082906/ArPot.dll"
    t3 = "D:/ProgramFiles/Anaconda3/Library/bin/pkgdata.exe"
    testfiles = [t1,t2,t3]
    

    host_info(True,False)
    outputs = []
    for t in testfiles:
        o1 = pefile_dump(t) #OK
        o2 = file_info(t)
    outputs.extend([o1,o2])
    
    for o in outputs:
        print(o)
