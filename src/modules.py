import os
import time
from threading import Thread
from queue import Queue
from settings import baseDir
import analysis

pendingFiles = Queue()
processedFiles = Queue()
class DirWalkerThread(Thread):
    def __init__(self, directory):
        Thread.__init__(self)
        self.dir = directory

    def run(self):
        fs = self.readDir(self.dir)
        print(fs)
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

class FileProcessor(Thread):

    def __init__(self):
        Thread.__init__(self)
    
    def run(self):
        while not pendingFiles.empty():
            filename = pendingFiles.get()
            analysis.byteAnalysis(filename)
            processedFiles.put(filename)


def InitiateDirWalkers():
    walkPaths = [os.path.join(baseDir,subDir) for subDir in os.listdir(baseDir)]
    threads = [DirWalkerThread(walkPath) for walkPath in walkPaths]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

def InitiateFileProcessors(threadCount):
    threads = [FileProcessor() for i in range(threadCount)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

if __name__ == '__main__':
    InitiateDirWalkers()
    start2 = time.time()
    InitiateFileProcessors(3)
    end2 = time.time()

    print("with multithread:{},{},{}".format(start2,end2,end2-start2))