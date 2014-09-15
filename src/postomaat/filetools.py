import os
import time

class FileReloader(object):
    """Caches file contents in memory and auto-reloads if file changes on disk"""
    def __init__(self,filename,reload_after=0):
        """
        :param filename: full path to the filename to load into memory
        :param reload_after: minimum time between reloads.
        :return:
        """
        self.filename=filename

        self.reload_after=reload_after
        self.lastreload=0
        self.content=None

    def _reloadifnecessary(self):
        """
        reload the file if it has changed on disk and minimum check time has passed
        :return:
        """
        now=time.time()
        #check if reloadinterval has passed
        if now-self.lastreload<self.reload_after:
            return
        if self.file_changed():
            self._reload()

    def _reload(self):
        """
        really reload the file
        :return:
        """
        statinfo=os.stat(self.filename)
        ctime=statinfo.st_ctime
        self.lastreload=ctime
        self.content=open(self.filename,'r').read()

    def file_changed(self):
        """returns True if the file has changed on disk since the last reload"""
        if not os.path.isfile(self.filename):
            return False
        statinfo=os.stat(self.filename)
        ctime=statinfo.st_ctime
        if ctime>self.lastreload:
            return True
        return False

    def get_content(self):
        """returns the current file content"""
        self._reloadifnecessary()
        return self.content


class ListConfigFile(FileReloader):
    """Helper around FileReloader which stores all lines in a list.
    Comments are ignored
    leading/trailing whitespace is stripped from all lines
    empty lines are ignored
    """

    def __init__(self,filename,reload_after=0,lowercase=False):
        FileReloader.__init__(self,filename,reload_after=0)
        self.lowercase=lowercase
        self.content=[]

    def _reload(self):
        statinfo=os.stat(self.filename)
        ctime=statinfo.st_ctime
        self.lastreload=ctime
        fp=open(self.filename,'r')
        lines=fp.readlines()
        fp.close()
        newcontent=[]
        for line in lines:
            line=line.strip()
            if line=="":
                continue
            if line.startswith('#'):
                continue
            if self.lowercase==True:
                line=line.lower()
            newcontent.append(line)
        self.content=newcontent



