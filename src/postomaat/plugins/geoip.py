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
    have_geoip = 1
except:
    try:
        import GeoIP
        have_geoip = 2
    except:
        have_geoip = 0


class FuFileCache(object):
    __shared_state = {}
            
    def _reallyloadData(self, filename):
        raise NotImplementedError()

    def __init__(self, filename, **kw):
        self.__dict__ = self.__shared_state

        if not hasattr(self, 'lock'):
            self.lock=Lock()
        if not hasattr(self,'logger'):
            self.logger=logging.getLogger(str(self))
        if not hasattr(self,'lastreload'):
            self.lastreload=0
        
        self.reloadifnecessary(filename)
        
    
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
        
        
        
        
class PyGeoIPCache(FuFileCache):        
    def __init__(self, filename, **kw):
        FuFileCache.__init__(self, filename, **kw)
        self.geoip = None
        self.filename = filename
        
        
    def _reallyloadData(self, filename):
        self.geoip = pygeoip.GeoIP(filename)
        
    
    def country_code(self, ip):
        self.reloadifnecessary(self.filename)
        cc = u''
        try:
            cc = self.geoip.country_code_by_addr(ip)
        except:
            cc = None
        return cc
    
    def country_name(self, cc):
        self.reloadifnecessary(self.filename)
        country = 'unknown'
        if cc:
            i = pygeoip.const.COUNTRY_CODES.index(cc)
            country = pygeoip.const.COUNTRY_NAMES[i]
        return country



class GeoIPCache(PyGeoIPCache):        
    def _reallyloadData(self, filename):
        self.geoip = GeoIP.open(filename, GeoIP.GEOIP_STANDARD)
        
    
    def country_name(self, cc):
        self.reloadifnecessary(self.filename)
        country = 'unknown'
        if cc:
            cc = cc.upper()
            if cc in GeoIP.country_names:
                country = GeoIP.country_names[cc]
        return country
    
    
        
        
class GeoIPPlugin(ScannerPlugin):
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.geoip = None
        
        self.requiredvars={
            'database':{
                'default':'/var/lib/geoip/GeoIP.dat',
                'description':'location of the MaxMind GeopIP database file',
            },
            'blacklist':{
                'default':'',
                'description':'list of countries you do not want to receive mail from.',
            },
            'whitelist':{
                'default':'',
                'description':'list of countries you want want to receive mail from. all other countries will be rejected. If you specify a whitelist, the blacklist will have no function.',
            },
            'on_unknown':{
                'default':'DUNNO',
                'description':'what to do with unknown countries? this affects local IP-addresses. Set this to DUNNO or REJECT',
            },
        }
        
        
        
    def examine(self,suspect):
        if have_geoip == 0:
            return DUNNO
        
        database = self.config.get('GeoIP', 'database')
        if not os.path.exists(database):
            return DUNNO
        if not self.geoip and have_geoip == 1:
            self.geoip = PyGeoIPCache(database)
        elif not self.geoip and have_geoip == 2:
            self.geoip = GeoIPCache(database)
        
        client_address=suspect.get_value('client_address')
        if client_address is None:
            self.logger.info('No client address found')
            return DUNNO
        
        bl = self.config.get('GeoIP', 'blacklist').strip()
        blacklist = []
        if bl:
            blacklist = [i.strip() for i in bl.split(',')]
        wl = self.config.get('GeoIP', 'whitelist').strip()
        whitelist = []
        if wl:
            whitelist = [i.strip() for i in wl.split(',')]
        on_unknown = self.config.get('GeoIP', 'on_unknown')
        unknown = DUNNO
        if on_unknown.strip().upper() == 'REJECT':
            unknown = REJECT
        
        cc = self.geoip.country_code(client_address)
        cn = self.geoip.country_name(cc)
        
        action = DUNNO
        message = None
        
        if cn == 'unknown':
            action = unknown
        elif cc in blacklist or (whitelist and cc not in whitelist):
            action = REJECT
            
        if action == REJECT:
            message = 'this system does not accept mail from servers in your country "%s" - request whitelisting' % cn
            
        return action, message
        
        
    
    def lint(self):
        lint_ok = True
        
        if have_geoip == 0:
            print 'No geoip module installed - this plugin will do nothing'
            lint_ok = False
        elif have_geoip == 1:
            print 'using pygeoip'
        elif have_geoip == 2:
            print 'using maxmind geoip'
        
            
        database = self.config.get('GeoIP', 'database')
        if not os.path.exists(database):
            print 'Could not find geoip database file - this plugin will do nothing'
            lint_ok = False
        
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
        
        return lint_ok
        
        
        
