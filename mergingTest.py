import os
import time
from threading import Thread
from queue import Queue
import re

pendingFiles = Queue()
processedFiles = Queue()

class DirWalkerThread(Thread):
    def __init__(self, directory):
        Thread.__init__(self)
        self.dir = directory

    def run(self):
        fs = self.readDir(self.dir)
        for f in fs:
            pendingFiles.put(f)

    def readDir(self,directory):
        myFiles = []
        myDirs = []
        for root, dirs, files in os.walk(directory):
            for f in files:
                myFiles.append(os.path.join(root,f))
            for d in dirs:
                myDirs.append(os.path.join(root,d))
        return myFiles

class FileProcesser(Thread):

    def __init__(self):
        Thread.__init__(self)
    
    def run(self):
        while not pendingFiles.empty():
            filename = pendingFiles.get()
            self.byteAnalysis(filename)
            info = self.sigcheck(filename)
            print(info)
            processedFiles.put(filename)
        print("file process finished")

    def byteAnalysis(self,filename):
        with open(filename,'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                self.processChunks(chunk)

    def processChunks(self,chunk):
        chunklen = len(chunk)
        ffbyte = chunk.find(b'\xff')
        fabyte = chunk.find(b'\xfa')

    def sigcheck(self,filepath):
        """
        判斷檔案(參數filepath)是否具有可信認之數位簽章，使用sigcheck.exe 
        
        參考網址 https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck
        
        ##### 重要備註 ######
        signer是可以被修改的(打開檔案可修改byte)，要進一步判斷是否有被修改過?
        哪些signer是安全的?    
        CMD 有編碼問題!!! 先用except error帶過
        """
        try:
            # 用 sigcheck下指令
            output_str = os.popen('sigcheck -i -nobanner ' + filepath).read()
            str_list = re.findall(r"\w+.+", output_str)  # 將結果切成 list

            # 確認是否有簽章，若無會回傳 None，若有簽章再看看是誰簽的
            # if re.search('Verified:\tSigned', output_str) != None:   # 從整串指令回傳的str中找字串比對
                # str_list = re.findall(r"\w+.+", output_str)          # 將結果切成 list

            if 'Verified:\tSigned' in str_list:                        # 先切割字串再比對

                signer_arr = []
                signer_index = str_list.index('Signers:')

                # print(str_list)

                signer_index += 1
                signer_arr.append(str_list[signer_index])  # 第一個 signer

                # 列出所有 signer
                while re.search(r':$', str_list[signer_index+9]) == None:
                    signer_arr.append(str_list[signer_index+9])
                    signer_index += 9
                return signer_arr  #有簽章，只有signer

            else:
                return None  #沒有簽章
        
        except UnicodeDecodeError as error:
            return 'error'


def InitiateDirWalkers():
    threads = [DirWalkerThread("Data\\data1"),DirWalkerThread("Data\\data2"),DirWalkerThread("Data\\data3"),DirWalkerThread("Data\\web")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

def InitiateFileProcessors():
    threads = [FileProcesser(),FileProcesser(),FileProcesser(),FileProcesser()]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    InitiateDirWalkers()

    start2 = time.time()
    InitiateFileProcessors()
    end2 = time.time()
    print("with multithread:{},{},{}".format(start2,end2,end2-start2))
