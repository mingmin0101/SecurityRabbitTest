import os
import time
from threading import Thread
from queue import Queue

myQueue = Queue()

class DirWalkerThread(Thread):
    def __init__(self, directory):
        Thread.__init__(self)
        self.dir = directory

    def run(self):
        fs = readDir(self.dir)
        for f in fs:
            myQueue.put(f)

def readDir(directory):
    myFiles = []
    myDirs = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            myFiles.append(os.path.join(root,f))
        for d in dirs:
            myDirs.append(os.path.join(root,d))
    return myFiles

def processPendingFiles(fileQueue):
    with open(myQueue.get(),'rb') as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            print("chunk: {}".format(chunk))


def exampleWithoutMultiThread():
    start = time.time()
    info = readDir("Data")
    end = time.time()
    print("without multithread:{},{},{}".format(start,end,end-start))

def exampleWithMultiThread():
    start2 = time.time()
    threads = [DirWalkerThread("Data\\data1"),DirWalkerThread("Data\\data2"),DirWalkerThread("Data\\data3"),DirWalkerThread("Data\\web")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    end2 = time.time()
    print("with multithread:{},{},{}".format(start2,end2,end2-start2))

#what we know
# 1. f.read(CHUNK_SIZE) CHUNK_SIZE does significantly increase performance
# 2. multithreading does increase performance by approximately 50% faster
def fileReadSize(chunkSize):
    filename = 'Data/data1/python.exe'
    readstart = time.time()
    myExe = bytearray(b'')
    with open(filename,'rb') as f:
        while True:
            chunk = f.read(chunkSize)
            if not chunk:
                break
            myExe.extend(chunk)
    readend = time.time()
    print("fileReadTime with size {} :{},{},{}".format(chunkSize,readstart,readend,readend-readstart))

if __name__ == '__main__':
    exampleWithoutMultiThread()
    exampleWithMultiThread()
    fileReadSize(1)
    fileReadSize(8192)
    
    #print(myExe)
            
