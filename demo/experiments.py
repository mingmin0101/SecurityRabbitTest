import os
import time
from threading import Thread
from queue import Queue
from settings import baseDir

myQueue = Queue()

class DirWalkerThread(Thread):
    def __init__(self, directory):
        Thread.__init__(self)
        self.dir = directory

    def run(self):
        fs = readDir(self.dir)
        for f in fs:
            myQueue.put(f)

class FileProcessor(Thread):
    def __init__(self):
        Thread.__init__(self)
    
    def run(self):
        while not myQueue.empty():
            filename = myQueue.get()
            processFile(filename)

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
    walkPaths = [os.path.join(baseDir,subDir) for subDir in os.listdir(baseDir)]
    threads = [DirWalkerThread(walkPath) for walkPath in walkPaths]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
        
def proccessFileMultithread(threadCount):
    threads = [FileProcessor() for i in range(threadCount)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

def fileRead(filename,chunkSize):
    myExe = bytearray(b'')
    with open(filename,'rb') as f:
        while True:
            chunk = f.read(chunkSize)
            if not chunk:
                break
            myExe.extend(chunk)
    return myExe

def fileProcessExperiment():
    total = 0
    runTimes = 20
    threadCount = 4
    for i in range(runTimes):
        putFilesInQueue()
        start = time.time()
        proccessFileMultithread(1)
        end = time.time()
        duration = end-start
        print("process file without multithread:{},{},{}".format(start,end,duration))

        putFilesInQueue()
        start2 = time.time()
        proccessFileMultithread(threadCount)
        end2 = time.time()
        duration2 = end2-start2
        print("process file with multithread:{},{},{}".format(start2,end2,duration2))
        performaceDiff = duration/duration2
        print("performance difference: {}".format(performaceDiff))

        total += performaceDiff
    print("threadCount:{}  Average:{}".format(threadCount,total/runTimes))

def dirWalkExperiment():
    total = 0
    runTimes = 20
    for i in range(runTimes):
        start = time.time()
        files = readDir(baseDir)
        for f in files:
            myQueue.put(f)
        end = time.time()
        duration = end - start
        print("walk directory without multithread:{},{},{}".format(start,end,duration))

        start2 = time.time()
        putFilesInQueue()
        end2 = time.time()
        duration2 = end2 - start2
        print("walk directory with multithread:{},{},{}".format(start2,end2,duration2))
        performaceDiff = duration/duration2
        print("performance difference: {}".format(performaceDiff))
        total += performaceDiff
    print("Average:{}".format(total/runTimes))

def fileReadExperiment():
    runTimes = 20
    total = 0
    for i in range(runTimes):
        filename = os.path.join(baseDir,'testdir1','python.exe')

        start = time.time()
        chunksize = 1
        fileRead(filename,chunksize)
        end = time.time()
        duration = end-start
        print("fileReadTime with size {} :{},{},{}".format(chunksize,start,end,duration))

        start2 = time.time()
        chunksize2 = 8192
        fileRead(filename,chunksize2)
        end2 = time.time()
        duration2 = end2-start2
        print("fileReadTime with size {} :{},{},{}".format(chunksize2,start2,end2,duration2))
        performanceDiff = duration/duration2
        print("fileReadTime difference between [{},{}] : {}".format(chunksize,chunksize2,performanceDiff))
        total += performanceDiff
    print("Average:{}".format(total/runTimes))

if __name__ == '__main__':
    #fileProcessExperiment()
    dirWalkExperiment()
    #fileReadExperiment()
    


