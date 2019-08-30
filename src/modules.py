import os
import time
from threading import Thread
from queue import Queue
from settings import baseDir,dataDir
import analysis
import pandas

pendingFiles = Queue()
processedFiles = Queue()
processedDicts = Queue()

class DirWalkerThread(Thread):
    def __init__(self, directory):
        Thread.__init__(self)
        self.dir = directory
        self.addFileType = ['.exe']

    def run(self):
        files = self.readDir(self.dir)
        for f in files:
            pendingFiles.put(f)
            print("{} added to pendingFiles".format(f))

    def readDir(self,directory):
        myFiles = []
        myDirs = []
        for root, dirs, files in os.walk(directory):
            for f in files:
                if self.isExamineFileType(f):
                    myFiles.append(os.path.join(root,f))
            for d in dirs:
                myDirs.append(os.path.join(root,d))
        return myFiles

    def isExamineFileType(self,filename):
        if os.path.splitext(filename)[-1] in self.addFileType:
            return True
        else:
            return False

class FileProcessor(Thread):
    def __init__(self):
        Thread.__init__(self)
    
    def run(self):
        while not pendingFiles.empty():
            filename = pendingFiles.get()
            analysis.pefile_dump(filename)
            file_info_dict = analysis.file_info(filename)
            processedDicts.put(file_info_dict)
            print("[{} files remaining] processing {}...".format(pendingFiles.qsize(),filename))


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

def main_process():
    all_files = []
    while not processedDicts.empty():
        all_files.append(processedDicts.get())
    df = pandas.DataFrame(all_files)
    df.to_excel(os.path.join(dataDir,"test.xlsx"),index=False)

if __name__ == '__main__':
    InitiateDirWalkers()
    start2 = time.time()
    InitiateFileProcessors(3)
    end2 = time.time()

    main_process()


    print("process time: {} {} {}".format(start2,end2,end2-start2))