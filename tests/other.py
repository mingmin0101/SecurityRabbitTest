import os

filename = "C:/Users/user/AppData/Local/LINE/bin/LineLauncher.exe"
def doAnalyze(self,filename):
    if os.path.splitext(filename)[-1] in self.addFileType:
        return True
    else:
        return False

