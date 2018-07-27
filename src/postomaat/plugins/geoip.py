# -*- coding: UTF-8 -*-
#   Copyright 2012-2018 Fumail Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#

"""
This plugin allows to reject mails based on the location of the sending server.

Set a blacklist to reject mail from specific countries.
Set a whitelist to accept mail from specific countries only, mail from all other countries will be rejected.

The python pygeoip module and the GeoIP-database from MaxMind are required. 
"""

import os
from postomaat.shared import ScannerPlugin, DUNNO, REJECT, apply_template, FileList

LIB_GEOIP_NONE = 0
LIB_GEOIP_PYGEOIP = 1
LIB_GEOIP_MAXMIND = 2

try:
    import pygeoip
    HAVE_GEOIP = LIB_GEOIP_PYGEOIP
except ImportError:
    pygeoip = None
    try:
        import GeoIP
        HAVE_GEOIP = LIB_GEOIP_MAXMIND
    except ImportError:
        GeoIP = None
        HAVE_GEOIP = LIB_GEOIP_NONE



class PyGeoIPCache(FileList):
    def __init__(self, filename, **kw):
        FileList.__init__(self, filename, **kw)
        self.geoip = None
        
        
    def _reload(self):
        self.geoip = pygeoip.GeoIP(self.filename)
        self.logger.debug('loaded geoip database %s' % self.filename)
        
    
    def country_code(self, ip):
        self._reload_if_necessary()
        try:
            cc = self.geoip.country_code_by_addr(ip)
        except Exception as e:
            self.logger.debug('Failed to get country code for %s: %s' % (ip, str(e)))
            cc = None
        return cc
    
    def country_name(self, cc):
        self._reload_if_necessary()
        country = 'unknown'
        if cc:
            i = pygeoip.const.COUNTRY_CODES.index(cc)
            country = pygeoip.const.COUNTRY_NAMES[i]
        return country



class GeoIPCache(PyGeoIPCache):        
    def __reload(self):
        self.geoip = GeoIP.open(self.filename, GeoIP.GEOIP_STANDARD)
        self.logger.debug('loaded geoip database %s' % self.filename)
        
    
    def country_name(self, cc):
        self._reload_if_necessary()
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
        if HAVE_GEOIP == LIB_GEOIP_PYGEOIP:
            self.geoip = PyGeoIPCache(None)
        elif HAVE_GEOIP == LIB_GEOIP_MAXMIND:
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
        if HAVE_GEOIP == LIB_GEOIP_NONE:
            return DUNNO
        
        database = self.config.get(self.section, 'database')
        if not os.path.exists(database):
            return DUNNO
        self.geoip.filename = database
        self.geoip._reload_if_necessary()
        
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
        
        if HAVE_GEOIP == LIB_GEOIP_NONE:
            print('No geoip module installed - this plugin will do nothing')
            lint_ok = False
        elif HAVE_GEOIP == LIB_GEOIP_PYGEOIP:
            print('using pygeoip')
        elif HAVE_GEOIP == LIB_GEOIP_MAXMIND:
            print('using maxmind geoip')
        
            
        database = self.config.get(self.section, 'database')
        if not os.path.exists(database):
            print('Could not find geoip database file - this plugin will do nothing')
            lint_ok = False
        else:
            print('Using GeoIP Database in %s' % database)
        
        if not self.checkConfig():
            print('Error checking config')
            lint_ok = False

        blacklist = self._get_list('blacklist')
        whitelist = self._get_list('whitelist')
        if not blacklist and not whitelist:
            print('Neither black nor white list defined')
            lint_ok = False
        elif blacklist and whitelist:
            print('Black and white list defined - only using blacklist')
            lint_ok = False
        else:
            print('Blacklist: %s' % blacklist)
            print('Whitelist: %s' % whitelist)

        return lint_ok
        
        

    def __str__(self):
        return "GeoIPPlugin"
