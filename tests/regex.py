import re

myStr = """
<attribute>Verified:Signed
<attribute>Link date:?? 05:43 2019/9/4
<attribute>Signing date:?? 06:00 2019/9/4
<attribute>Catalog:c:/users/user/appdata/local/line/bin/LineLauncher.exe
<attribute>Signers:
<Certificate> LINE Corporation
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Code Signing
<Certi Info>Cert Issuer:Symantec Class 3 Extended Validation Code Signing CA - G2
<Certi Info>Serial Number:6E EB 30 D3 BE 83 8F 80 A3 E1 FC 1F 75 CB 2E 30
<Certi Info>Thumbprint:A97F6DF9FE8DBEB2B347D60715A9C2AB912E1D4F
<Certi Info>Algorithm:sha256RSA
<Certi Info>Valid from:?? 08:00 2018/5/8
<Certi Info>Valid to:?? 07:59 2020/5/8
<Certificate> Symantec Class 3 Extended Validation Code Signing CA - G2
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Code Signing
<Certi Info>Cert Issuer:VeriSign Class 3 Public Primary Certification Authority - G5
<Certi Info>Serial Number:19 1A 32 CB 75 9C 97 B8 CF AC 11 8D D5 12 7F 49
<Certi Info>Thumbprint:5B8F88C80A73D35F76CD412A9E74E916594DFA67
<Certi Info>Algorithm:sha256RSA
<Certi Info>Valid from:?? 08:00 2014/3/4
<Certi Info>Valid to:?? 07:59 2024/3/4
<Certificate> VeriSign
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Server Auth, Client Auth, Email Protection, Code Signing
<Certi Info>Cert Issuer:VeriSign Class 3 Public Primary Certification Authority - G5
<Certi Info>Serial Number:18 DA D1 9E 26 7D E8 BB 4A 21 58 CD CC 6B 3B 4A
<Certi Info>Thumbprint:4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5
<Certi Info>Algorithm:sha1RSA
<Certi Info>Valid from:?? 08:00 2006/11/8
<Certi Info>Valid to:?? 07:59 2036/7/17
<attribute>Counter Signers:
<Certificate> Symantec Time Stamping Services Signer - G4
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Timestamp Signing
<Certi Info>Cert Issuer:Symantec Time Stamping Services CA - G2
<Certi Info>Serial Number:0E CF F4 38 C8 FE BF 35 6E 04 D8 6A 98 1B 1A 50
<Certi Info>Thumbprint:65439929B67973EB192D6FF243E6767ADF0834E4
<Certi Info>Algorithm:sha1RSA
<Certi Info>Valid from:?? 08:00 2012/10/18
<Certi Info>Valid to:?? 07:59 2020/12/30
<Certificate> Symantec Time Stamping Services CA - G2
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Timestamp Signing
<Certi Info>Cert Issuer:Thawte Timestamping CA
<Certi Info>Serial Number:7E 93 EB FB 7C C6 4E 59 EA 4B 9A 77 D4 06 FC 3B
<Certi Info>Thumbprint:6C07453FFDDA08B83707C09B82FB3D15F35336B1
<Certi Info>Algorithm:sha1RSA
<Certi Info>Valid from:?? 08:00 2012/12/21
<Certi Info>Valid to:?? 07:59 2020/12/31
<Certificate> Thawte Timestamping CA
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Timestamp Signing
<Certi Info>Cert Issuer:Thawte Timestamping CA
<Certi Info>Serial Number:00
<Certi Info>Thumbprint:BE36A4562FB2EE05DBB3D32323ADF445084ED656
<Certi Info>Algorithm:md5RSA
<Certi Info>Valid from:?? 08:00 1997/1/1
<Certi Info>Valid to:?? 07:59 2021/1/1
<attribute>Signing date:?? 06:00 2019/9/4
<attribute>Catalog:c:/users/user/appdata/local/line/bin/LineLauncher.exe
<attribute>Signers:
<Certificate> LINE Corporation
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Code Signing
<Certi Info>Cert Issuer:Symantec Class 3 Extended Validation Code Signing CA - G2
<Certi Info>Serial Number:6E EB 30 D3 BE 83 8F 80 A3 E1 FC 1F 75 CB 2E 30
<Certi Info>Thumbprint:A97F6DF9FE8DBEB2B347D60715A9C2AB912E1D4F
<Certi Info>Algorithm:sha256RSA
<Certi Info>Valid from:?? 08:00 2018/5/8
<Certi Info>Valid to:?? 07:59 2020/5/8
<Certificate> Symantec Class 3 Extended Validation Code Signing CA - G2
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Code Signing
<Certi Info>Cert Issuer:VeriSign Class 3 Public Primary Certification Authority - G5
<Certi Info>Serial Number:19 1A 32 CB 75 9C 97 B8 CF AC 11 8D D5 12 7F 49
<Certi Info>Thumbprint:5B8F88C80A73D35F76CD412A9E74E916594DFA67
<Certi Info>Algorithm:sha256RSA
<Certi Info>Valid from:?? 08:00 2014/3/4
<Certi Info>Valid to:?? 07:59 2024/3/4
<Certificate> VeriSign
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Server Auth, Client Auth, Email Protection, Code Signing
<Certi Info>Cert Issuer:VeriSign Class 3 Public Primary Certification Authority - G5
<Certi Info>Serial Number:18 DA D1 9E 26 7D E8 BB 4A 21 58 CD CC 6B 3B 4A
<Certi Info>Thumbprint:4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5
<Certi Info>Algorithm:sha1RSA
<Certi Info>Valid from:?? 08:00 2006/11/8
<Certi Info>Valid to:?? 07:59 2036/7/17
<attribute>Counter Signers:
<Certificate> Symantec SHA256 TimeStamping Signer - G3
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Timestamp Signing
<Certi Info>Cert Issuer:Symantec SHA256 TimeStamping CA
<Certi Info>Serial Number:7B D4 E5 AF BA CC 07 3F A1 01 23 04 22 41 4D 12
<Certi Info>Thumbprint:A9A4121063D71D48E8529A4681DE803E3E7954B0
<Certi Info>Algorithm:sha256RSA
<Certi Info>Valid from:?? 08:00 2017/12/23
<Certi Info>Valid to:?? 07:59 2029/3/23
<Certificate> Symantec SHA256 TimeStamping CA
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:Timestamp Signing
<Certi Info>Cert Issuer:VeriSign Universal Root Certification Authority
<Certi Info>Serial Number:7B 05 B1 D4 49 68 51 44 F7 C9 89 D2 9C 19 9D 12
<Certi Info>Thumbprint:6FC9EDB5E00AB64151C1CDFCAC74AD2C7B7E3BE4
<Certi Info>Algorithm:sha256RSA
<Certi Info>Valid from:?? 08:00 2016/1/12
<Certi Info>Valid to:?? 07:59 2031/1/12
<Certificate> VeriSign Universal Root Certification Authority
<Certi Info>Cert Status:Valid
<Certi Info>Valid Usage:All
<Certi Info>Cert Issuer:VeriSign Universal Root Certification Authority
<Certi Info>Serial Number:40 1A C4 64 21 B3 13 21 03 0E BB E4 12 1A C5 1D
<Certi Info>Thumbprint:3679CA35668772304D30A5FB873B0FA77BB70D54
<Certi Info>Algorithm:sha256RSA
<Certi Info>Valid from:?? 08:00 2008/4/2
<Certi Info>Valid to:?? 07:59 2037/12/2
<attribute>Company:LINE Corporation
<attribute>Description:LINE
<attribute>Product:LINE
<attribute>Prod version:1.0.0.19
<attribute>File version:1.0.0.19
<attribute>MachineType:32-bit
"""

iter = re.finditer(r'<Certificate>',myStr)
for i in iter:
    print(i.span(),i.group())