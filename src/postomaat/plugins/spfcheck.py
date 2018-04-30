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

from postomaat.shared import ScannerPlugin, DUNNO, strip_address, extract_domain, apply_template, \
    FileList, string_to_actioncode, get_default_cache
from postomaat.extensions.sql import SQL_EXTENSION_ENABLED, get_session, get_domain_setting
import os
try:
    import spf
    HAVE_SPF = True
except ImportError:
    spf = None
    HAVE_SPF = False
    
try:
    from netaddr import IPAddress, IPNetwork
    HAVE_NETADDR = True
except ImportError:
    IPAddress = IPNetwork = None
    HAVE_NETADDR = False

    

class SPFPlugin(ScannerPlugin):
    """This plugin performs SPF validation using the pyspf module https://pypi.python.org/pypi/pyspf/
    by default, it just logs the result (test mode)

    to enable actual rejection of messages, add a config option on_<resulttype> with a valid postfix action. eg:

    on_fail = REJECT

    valid result types are: 'pass', 'permerror', 'fail', 'temperror', 'softfail', 'none', and 'neutral'
    """
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.requiredvars={
            'ip_whitelist_file':{
                'default':'',
                'description':'file containing a list of ip adresses to be exempted from SPF checks. Supports CIDR notation if the netaddr module is installed. 127.0.0.0/8 is always exempted',
            },
            'domain_selective_spf_file':{
                'default':'',
                'description':'if this is non-empty, only sender domains in this file will be checked for SPF',
            },
            'dbconnection':{
                'default':"mysql://root@localhost/spfcheck?charset=utf8",
                'description':'SQLAlchemy Connection string. Leave empty to disable SQL lookups',
            },
            'domain_sql_query':{
                'default':"SELECT check_spf from domain where domain_name=:domain",
                'description':'get from sql database :domain will be replaced with the actual domain name. must return field check_spf',
            },
            'on_fail':{
                'default':'DUNNO',
                'description':'Action for SPF fail.',
            },
            'on_softfail':{
                'default':'DUNNO',
                'description':'Action for SPF softfail.',
            },
            'messagetemplate':{
                'default':'SPF ${result} for domain ${from_domain} from ${client_address} : ${explanation}'
            }
        }
        
        self.ip_whitelist_loader=None
        self.ip_whitelist=[] # either a list of plain ip adress strings or a list of IPNetwork if netaddr is available

        self.selective_domain_loader=None
    
    
    def check_this_domain(self, from_domain):
        do_check = False
        selective_sender_domain_file=self.config.get(self.section,'domain_selective_spf_file','').strip()
        if selective_sender_domain_file != '' and os.path.exists(selective_sender_domain_file):
            if self.selective_domain_loader is None:
                self.selective_domain_loader=FileList(selective_sender_domain_file,lowercase=True)
            if from_domain.lower() in self.selective_domain_loader.get_list():
                do_check = True
                
        if not do_check:
            dbconnection = self.config.get(self.section, 'dbconnection', '').strip()
            sqlquery = self.config.get(self.section, 'domain_sql_query')
            
            if dbconnection!='' and SQL_EXTENSION_ENABLED:
                cache = get_default_cache()
                do_check = get_domain_setting(from_domain, dbconnection, sqlquery, cache, self.section, False, self.logger)
                
            elif dbconnection!='' and not SQL_EXTENSION_ENABLED:
                self.logger.error('dbconnection specified but sqlalchemy not available - skipping db lookup')
                
        return do_check


    def is_private_address(self,addr):
        if addr=='127.0.0.1' or addr=='::1' or addr.startswith('10.') or addr.startswith('192.168.') or addr.startswith('fe80:'):
            return True
        if not addr.startswith('172.'):
            return False
        for i in range(16,32):
            if addr.startswith('172.%s'%i):
                return True
        return False


    def ip_whitelisted(self,addr):
        if self.is_private_address(addr):
            return True

        #check ip whitelist
        ip_whitelist_file=self.config.get(self.section,'ip_whitelist_file', '').strip()
        if ip_whitelist_file != '' and os.path.exists(ip_whitelist_file):
            plainlist = []
            if self.ip_whitelist_loader is None:
                self.ip_whitelist_loader=FileList(ip_whitelist_file,lowercase=True)

            if self.ip_whitelist_loader.file_changed():
                plainlist=self.ip_whitelist_loader.get_list()

                if HAVE_NETADDR:
                    self.ip_whitelist=[IPNetwork(x) for x in plainlist]
                else:
                    self.ip_whitelist=plainlist

            if HAVE_NETADDR:
                checkaddr=IPAddress(addr)
                for net in self.ip_whitelist:
                    if checkaddr in net:
                        return True
            else:
                if addr in plainlist:
                    return True
        return False


    def examine(self,suspect):
        if not HAVE_SPF:
            return DUNNO
        
        client_address=suspect.get_value('client_address')
        helo_name=suspect.get_value('helo_name')
        sender=suspect.get_value('sender')
        if client_address is None or helo_name is None or sender is None:
            self.logger.error('missing client_address or helo or sender')
            return DUNNO

        if self.ip_whitelisted(client_address):
            self.logger.info("Client %s is whitelisted - no SPF check"%client_address)
            return DUNNO

        sender_email = strip_address(sender)
        if sender_email=='' or sender_email is None:
            return DUNNO
        
        sender_domain = extract_domain(sender_email)
        if sender_domain is None:
            self.logger.error('no domain found in sender address %s' % sender_email)
            return DUNNO
        
        if not self.check_this_domain(sender_domain):
            self.logger.debug('skipping SPF check for %s' % sender_domain)
            return DUNNO

        result, explanation = spf.check2(client_address, sender_email, helo_name)
        suspect.tags['spf'] = result
        if result != 'none':
            self.logger.info('SPF client=%s, sender=%s, h=%s result=%s : %s' % (client_address, sender_email, helo_name, result,explanation))
        
        action = DUNNO
        message = apply_template(self.config.get(self.section, 'messagetemplate'), suspect, dict(result=result, explanation=explanation))

        configopt = 'on_%s' % result
        if self.config.has_option(self.section, configopt):
            action=string_to_actioncode(self.config.get(self.section, configopt))

        return action, message
         
        
    
    def lint(self):
        lint_ok = True
        
        if not HAVE_SPF:
            print('pyspf or pydns module not installed - this plugin will do nothing')
            lint_ok = False
            
        if not HAVE_NETADDR:
            print('WARNING: netaddr python module not installed - IP whitelist will not support CIDR notation')

        if not self.checkConfig():
            print('Error checking config')
            lint_ok = False
            
        selective_sender_domain_file=self.config.get(self.section,'domain_selective_spf_file','').strip()
        if selective_sender_domain_file != '' and not os.path.exists(selective_sender_domain_file):
            print("domain_selective_spf_file %s does not exist" % selective_sender_domain_file)
            lint_ok = False
            
        ip_whitelist_file=self.config.get(self.section,'ip_whitelist_file', '').strip()
        if ip_whitelist_file != '' and os.path.exists(ip_whitelist_file):
            print("ip_whitelist_file %s does not exist - IP whitelist is disabled" % ip_whitelist_file)
            lint_ok = False
        
        sqlquery = self.config.get(self.section, 'domain_sql_query')
        dbconnection = self.config.get(self.section, 'dbconnection', '').strip()
        if not SQL_EXTENSION_ENABLED and dbconnection != '':
            print('SQLAlchemy not available, cannot use SQL backend')
            lint_ok = False
        elif dbconnection == '':
            print('No DB connection defined. Disabling SQL backend')
        else:
            if not sqlquery.lower().startswith('select '):
                lint_ok = False
                print('SQL statement must be a SELECT query')
            if lint_ok:
                try:
                    conn=get_session(dbconnection)
                    conn.execute(sqlquery, {'domain':'example.com'})
                except Exception as e:
                    lint_ok = False
                    print(str(e))
        
        return lint_ok
    
    
    
    def __str__(self):
        return "SPF"
