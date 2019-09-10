import os
import time
import multiprocessing
import logging
import pandas

from settings import baseDir,dataDir
import analysis
import argparse
import sys


# exists problem when using multiprocessing Queue program won't end
def read_directory(directory, pending_file_queue, pending_dir_queue, examineFileType = ['.exe']):
    for root, dirs, files in os.walk(directory):
        for f in files:
            if os.path.splitext(f)[-1] in examineFileType:
                file_name = os.path.join(root,f)
                pending_file_queue.put(file_name)
                print("{} Added to pending_file_queue... ".format(file_name))
        for d in dirs:
            directory_name = os.path.join(root,d)
            pending_dir_queue.put(directory_name)

def process_files(pending_file_queue, processed_file_queue, problem_file_queue):
    try:
        while not pending_file_queue.empty():
            file_name = pending_file_queue.get()
            analysis.pefile_dump(file_name)
            file_info = analysis.file_info(file_name)
            processed_file_queue.put(file_info)
            print("[{} files remaining] Finished Processing {}...".format(pending_file_queue.qsize(),file_name))
    except:
        logging.exception('Exception Occured')
        raise

def get_runtime(func):
    start = time.time()
    func()
    end = time.time()
    duration = end - start
    return duration


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()
    parser.add_argument("directories", nargs="+", help="the root directory(s) you want to scan")
    parser.add_argument("--hostInfo", dest="hostInfo", action="store_true", help="set to True to scan hostInfo")
    parser.add_argument("--pefileDump", dest="pefileDump", action="store_true", help="set to True to pefileDump")
    args = parser.parse_args()
    
    manager = multiprocessing.Manager()
    problem_file_queue = manager.Queue()
    pending_file_queue = manager.Queue()
    pending_dir_queue = manager.Queue()
    processed_file_queue = manager.Queue()

    producers = multiprocessing.Pool()
    for directory in args.directories:
        producers.apply_async(read_directory, args = (directory, pending_file_queue, pending_dir_queue))
    producers.close()
    producers.join()

    consumers = multiprocessing.Pool()
    for i in range(10):
        consumers.apply_async(process_files, args = (pending_file_queue, processed_file_queue, problem_file_queue))
    consumers.close()
    consumers.join()


    all_files = []
    while not processed_file_queue.empty():
        all_files.append(processed_file_queue.get())
    df = pandas.DataFrame(all_files)
    df.to_excel(os.path.join(dataDir,'exeInfo.xlsx'))

    
    # round1
    # processed D:/ProgramFiles with multiprocess: 123.82507729530334 sec
    # processed D:/ProgramFiles with singleprocess: 354.9449689388275 sec

    # round2
    # processed D:/ with multiprocess: 277.9546284675598 sec
    # processed D:/ with singleprocess: 652.4830689430237 sec
    
    # Error Report
    # OSError: [WinError 1920] 系統無法存取該檔案。: 'C:/Users/user\\AppData\\Local\\Microsoft\\WindowsApps\\protocolhandler.exe'

    # Race condition in pefileIndex pefileInfo