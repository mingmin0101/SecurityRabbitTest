import pefile

def __internet_ability(pe_file):
    '''
    連網能力判斷
    '''
    NETWORKING_AND_INTERNET = ['dnsapi.dll', 'dhcpcsvc.dll', 'dhcpcsvc6.dll', 'dhcpsapi.dll', 'connect.dll', 
                           'httpapi.dll', 'netshell.dll', 'iphlpapi.dll', 'netfwv6.dll', 'dhcpcsvc.dll',
                           'hnetcfg.dll', 'netapi32.dll', 'qosname.dll', 'rpcrt4.dll', 'mgmtapi.dll', 'snmpapi.dll',
                           'smbwmiv2.dll', 'tapi32.dll', 'netapi32.dll', 'davclnt.dll', 'websocket.dll',
                           'bthprops.dll', 'wifidisplay.dll', 'wlanapi.dll', 'wcmapi.dll', 'fwpuclnt.dll',
                           'firewallapi.dll', 'winhttp.dll', 'wininet.dll', 'wnvapi.dll', 'ws2_32.dll',
                           'webservices.dll']
    used_dll = []
    pe_file.parse_data_directories()
    for entry in pe_file.DIRECTORY_ENTRY_IMPORT:
        try:
            dll = entry.dll.decode('utf-8').lower()
            if dll in NETWORKING_AND_INTERNET:
                used_dll.append(dll)
        except:
            print("Error in internet_ability")
    return used_dll

filename = "D:/ProgramFiles\AVAST Software\Avast\defs\19082906\ArPot.dll"
pe_file = pefile.PE(filename, fast_load=True)
output = __internet_ability(pe_file)
print(output)