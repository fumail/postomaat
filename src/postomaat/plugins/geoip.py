# -*- coding: UTF-8 -*-

"""
This plugin allows to reject mails based on the location of the sending server.

Set a blacklist to reject mail from specific countries.
Set a whitelist to accept mail from specific countries only, mail from all other countries will be rejected.

The python pygeoip module and the GeoIP-database from MaxMind are required. 
"""

from threading import Lock
import logging
import os

from postomaat.shared import ScannerPlugin, DUNNO, REJECT

try:
    import pygeoip
    have_geoip = True
except:
    have_geoip = False


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
        self.file = filename
        
        self._initlocal(**kw)
        
        self.reloadifnecessary(self.file)
        
    
    def reloadifnecessary(self, filename):
        """reload geoip database if file changed"""
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
        
        
        
        
class GeoIPCache(FuFileCache):        
    def _initlocal(self, **kw):
        if not os.path.exists(self.file):
            raise IOError('Could not find GeoIP database %s' % self.file)
             
        
    def _reallyloadData(self, filename):
        self.geoip = pygeoip.GeoIP(filename)
        
    
    def country_code(self, ip):
        cc = u''
        try:
            cc = self.geoip.country_code_by_addr(ip)
        except:
            cc = None
        return cc
    
    def country_name(self, cc):
        country = 'unknown'
        if cc:
            i = pygeoip.const.COUNTRY_CODES.index(cc)
            country = pygeoip.const.COUNTRY_NAMES[i]
        return country

        
        
        
class GeoIPPlugin(ScannerPlugin):
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        
        
    def examine(self,suspect):
        if not have_geoip:
            return DUNNO
        
        client_address=suspect.get_value('client_address')
        if client_address is None:
            self.logger.error('No client address found')
            return DUNNO
        
        bl = self.config.get('GeoIP', 'blacklist')
        blacklist = [i.strip() for i in bl.split(',')]
        wl = self.config.get('GeoIP', 'whitelist')
        whitelist = [i.strip() for i in wl.split(',')]
        on_unknown = self.config.get('GeoIP', 'on_unknown')
        unknown = DUNNO
        if on_unknown.strip().upper() == 'REJECT':
            unknown = REJECT
        
        database = self.config.get('GeoIP', 'database')
        self.geoip = GeoIPCache(database)
        
        cc = self.geoip.country_code(client_address)
        cn = self.geoip.country_name(cc)
        
        action = DUNNO
        message = None
        
        if cn == 'unknown':
            action = unknown
        elif cc in blacklist or (whitelist and cc not in whitelist):
            action = REJECT
            
        if action == REJECT:
            message = 'this system does not accept mail from your country "%s" - request whitelisting' % cn
            
        return action, message
         
        
    
    def lint(self):
        lint_ok = True
        
        if not have_geoip:
            print 'pygeoip module not installed - this plugin will do nothing'
            lint_ok = False
        
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
        
        return lint_ok
        
        
        