import os
import pefile
import peutils
from settings import baseDir,dataDir,confDir


def byteAnalysis(filename):
    with open(filename,'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            __processChunks(chunk)

def __processChunks(chunk):
    chunklen = len(chunk)
    ffbyte = chunk.find(b'\xff')
    fabyte = chunk.find(b'\xfa')

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
    
    return True

def check_pack(filepath):
    '''
    使用peutils套件，判斷檔案是否有進行加殼 
    '''
    pe_file = pefile.PE(filepath, fast_load=True)
    signature_file = os.path.join(confDir,'userdb_filter.txt')
    with open(signature_file,'r',encoding='utf-8') as f:
        sig_data = f.read()
    signatures = peutils.SignatureDatabase(data = sig_data)

    matches = signatures.match(pe_file, ep_only = True)
    matchall = signatures.match_all(pe_file, ep_only = True)
    
    return matchall

if __name__ == '__main__':
    filepath = os.path.join(baseDir,'testdir1','python.exe')
    pefile_dump(filepath)
    output = check_pack(filepath)
    print(output)
    