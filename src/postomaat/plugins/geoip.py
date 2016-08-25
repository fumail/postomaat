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

from postomaat.shared import ScannerPlugin, DUNNO, REJECT, apply_template

LIB_GEOIP_NONE = 0
LIB_GEOIP_PYGEOIP = 1
LIB_GEOIP_MAXMIND = 2

try:
    import pygeoip
    have_geoip = LIB_GEOIP_PYGEOIP
except ImportError:
    try:
        import GeoIP
        have_geoip = LIB_GEOIP_MAXMIND
    except ImportError:
        have_geoip = LIB_GEOIP_NONE


class FuFileCache(object):
    def _reallyloadData(self, filename):
        raise NotImplementedError()

    def __init__(self, filename, **kw):
        self.logger=logging.getLogger('postomaat.geoip.%s' % self.__class__)
        self.filename = filename

        if not hasattr(self, 'lock'):
            self.lock=Lock()
        if not hasattr(self,'logger'):
            self.logger=logging.getLogger(str(self))
        if not hasattr(self,'lastreload'):
            self.lastreload=0

        if self.filename:
            self.reloadifnecessary(self.filename)
        
    
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
        self.logger.debug('Filename %s stat: ctime=%s recorded ctime=%s' % (filename, ctime, self.lastreload))
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
        
        
    def _reallyloadData(self, filename):
        self.geoip = pygeoip.GeoIP(filename)
        self.logger.debug('loaded geoip database %s' % filename)
        
    
    def country_code(self, ip):
        self.reloadifnecessary(self.filename)
        try:
            cc = self.geoip.country_code_by_addr(ip)
        except Exception as e:
            self.logger.debug('Failed to get country code for %s: %s' % (ip, str(e)))
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
        if have_geoip == LIB_GEOIP_PYGEOIP:
            self.geoip = PyGeoIPCache(None)
        elif have_geoip == LIB_GEOIP_MAXMIND:
            self.geoip = GeoIPCache(None)
        else:
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
            'reject_message':{
                'default':'this system does not accept mail from servers in your country "${cn}" - request whitelisting',
                'description':'message displayed to client on reject. use ${cc} as placeholder for country code and ${cn} for English country name',
            },
        }



    def _get_list(self, list_type='blacklist'):
        data = self.config.get(self.section, list_type).strip()
        mylist = []
        if data:
            sep = ' '
            if ',' in data:
                sep = ','
            mylist = [i.strip() for i in data.split(sep)]
        return mylist
        
        
        
    def examine(self,suspect):
        if have_geoip == LIB_GEOIP_NONE:
            return DUNNO
        
        database = self.config.get(self.section, 'database')
        if not os.path.exists(database):
            return DUNNO
        self.geoip.filename = database
        self.geoip.reloadifnecessary(database)
        
        client_address=suspect.get_value('client_address')
        if client_address is None:
            self.logger.info('No client address found')
            return DUNNO
        
        blacklist = self._get_list('blacklist')
        whitelist = self._get_list('whitelist')
        on_unknown = self.config.get(self.section, 'on_unknown')
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
            rejmsg = self.config.get(self.section, 'reject_message').strip()
            message = apply_template(rejmsg, suspect, dict(cn=cn, cc=cc))

        self.logger.debug('IP: %s country: %s action: %s' % (client_address, cc, action))
        return action, message
        
        
    
    def lint(self):
        lint_ok = True
        
        if have_geoip == LIB_GEOIP_NONE:
            print 'No geoip module installed - this plugin will do nothing'
            lint_ok = False
        elif have_geoip == LIB_GEOIP_PYGEOIP:
            print 'using pygeoip'
        elif have_geoip == LIB_GEOIP_MAXMIND:
            print 'using maxmind geoip'
        
            
        database = self.config.get(self.section, 'database')
        if not os.path.exists(database):
            print 'Could not find geoip database file - this plugin will do nothing'
            lint_ok = False
        else:
            print 'Using GeoIP Database in %s' % database
        
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False

        blacklist = self._get_list('blacklist')
        whitelist = self._get_list('whitelist')
        if not blacklist and not whitelist:
            print 'Neither black nor white list defined'
            lint_ok = False
        elif blacklist and whitelist:
            print 'Black and white list defined - only using blacklist'
            lint_ok = False
        else:
            print 'Blacklist: %s' % blacklist
            print 'Whitelist: %s' % whitelist

        return lint_ok
        
        

    def __str__(self):
        return "GeoIPPlugin"
