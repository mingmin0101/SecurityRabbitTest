import string
import os
import math

printable_str = set(bytes(string.printable,'ascii'))
print(printable_str)
test = b'fd!$@$@#@8\n \r'
for t in test:
    print(bytes([t]))

print(len(test))

filename = "D:/Users/hank/Documents/Code/Cfamily/cpp/data_structure/hash_table.exe"
file_size = os.stat(filename)
print(file_size)

print(math.log(0.0,2))