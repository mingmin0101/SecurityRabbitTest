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

class FileProcesser(Thread):
    def __init__(self):
        Thread.__init__(self)
    
    def run(self):
        while not myQueue.empty():
            filename = myQueue.get()
            processFile(filename)
        print("file process finished")

def readDir(directory):
    myFiles = []
    myDirs = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            myFiles.append(os.path.join(root,f))
        for d in dirs:
            myDirs.append(os.path.join(root,d))
    return myFiles

def processFile(filename):
    with open(filename,'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            processChunks(chunk)

def processChunks(chunk):
    chunklen = len(chunk)
    ffbyte = chunk.find(b'\xff')
    fabyte = chunk.find(b'\xfa')

def putFilesInQueue():
    threads = [DirWalkerThread("Data\\data1"),DirWalkerThread("Data\\data2"),DirWalkerThread("Data\\data3"),DirWalkerThread("Data\\web")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
        
def proccessFileMultithread():
    threads = [FileProcesser(),FileProcesser(),FileProcesser(),FileProcesser()]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    putFilesInQueue()

    start = time.time()
    while not myQueue.empty():
        filename = myQueue.get()
        processFile(filename)
    end = time.time()
    print("without multithread:{},{},{}".format(start,end,end-start))

    start2 = time.time()
    proccessFileMultithread()
    end2 = time.time()
    print("with multithread:{},{},{}".format(start2,end2,end2-start2))


