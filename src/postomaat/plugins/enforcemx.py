# -*- coding: UTF-8 -*-

"""
This plugin allows you to configure from which IPs you 
are willing to accept mail for a given domain.

This can be useful if you provide shared hosting (many domains on one mail 
server) and some of the domains use a cloud based spam filter (= MX records 
not pointing directly to your hosting server). You can reject mail coming 
from unexpected hosts trying to bypass the spam filter. 
"""


import logging
import os
from threading import Lock

try:
    from netcidr import CIDR
    have_netcidr = True
except:
    have_netcidr = False


from postomaat.shared import ScannerPlugin, DUNNO, DEFER_IF_PERMIT, REJECT, strip_address, extract_domain


class FuFileCache(object):
    __shared_state = {}
            
    def _initlocal(self, **kw):
        pass
    
    def _reallyloadData(self, filename):
        raise NotImplementedError()

    def __init__(self, filename, **kw):
        self.__dict__ = self.__shared_state
        if not hasattr(self, 'uris'):
            self.uris=[]

        if not hasattr(self, 'lock'):
            self.lock=Lock()
        if not hasattr(self,'logger'):
            self.logger=logging.getLogger(str(self))
        if not hasattr(self,'lastreload'):
            self.lastreload=0
        self.filename = filename
        
        self._initlocal(**kw)
        
        self.reloadifnecessary(self.filename)
        
    
    def reloadifnecessary(self, filename):
        """reload database if file changed"""
        if not self.filechanged(filename):
            return
        if not self.lock.acquire():
            return
        try:
            self._loadData(filename)
        finally:
            self.lock.release()
        
        
    def filechanged(self, filename):
        statinfo=os.stat(filename)
        ctime=statinfo.st_ctime
        if ctime>self.lastreload:
            return True
        return False
    
    
    def _loadData(self, filename):
        """effectively loads the Data, do not call directly, only through reloadifnecessary"""
        #set last timestamp
        statinfo=os.stat(filename)
        ctime=statinfo.st_ctime
        self.lastreload=ctime
        self._reallyloadData(filename)
        
        
        
class MXCache(FuFileCache):        
    def _initlocal(self, **kw):
        self.mxnets = {}
             
        
    def _reallyloadData(self, filename):        
        handle=open(filename)
        for line in handle.readlines():
            line.strip()
            if line and not line.startswith('#'):
                data = line.split(None, 1)
                
                if len(data) != 2:
                    continue
                    
                domain = data[0]
                nets = data[1]
                
                if not domain in self.mxnets:
                    self.mxnets[domain] = []
                
                for item in nets.split(','):
                    item = item.strip()
                    item = CIDR(item)
                    if not item in self.mxnets[domain]:
                        self.mxnets[domain].append(item)
                        
    
    def permitted(self, domain, ip):
        self.reloadifnecessary(self.filename)
        
        #domain is not listed, we accept mail from everywhere
        if not domain in self.mxnets:
            return True
        
        perm = False
        for net in self.mxnets[domain]:
            if ip in net.iterIPs():
                perm = True
                break
        return perm
                    


class EnforceMX(ScannerPlugin):
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.mxcache = None
        
        
        
    def examine(self,suspect):
        if not have_netcidr:
            return DUNNO,None
        
        client_address=suspect.get_value('client_address')
        if client_address is None:
            self.logger.error('No client address found - skipping')
            return DUNNO
        
        to_address=suspect.get_value('recipient')
        if to_address==None:
            self.logger.warning('No RCPT address found')
            return DEFER_IF_PERMIT,'internal policy error(no from address)'
        
        to_address=strip_address(to_address)
        to_domain=extract_domain(to_address)
        
        if not self.mxcache:
            datafile = self.config.get('EnforceMX','datafile')
            if os.path.exists(datafile):
                self.mxcache = MXCache(datafile)
            else:
                return DUNNO,None
           
        action = DUNNO
        message = None 
        if not self.mxcache.permitted(to_domain, client_address):
            action = REJECT
            message = 'We do not accept mail for %s from %s. Please send to MX records!' % (to_domain, client_address)
            
        return action, message
    
    
    
    def lint(self):
        lint_ok = True
        
        if not have_netcidr:
            print 'netcidr python module not available - please install'
            lint_ok =  False
        
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
        
        datafile = self.config.get('EnforceMX','datafile')
        if not os.path.exists(datafile):
            print 'datafile not found - this plugin will not do anything'
            lint_ok = False
        
        return lint_ok
        
    
    
    
    