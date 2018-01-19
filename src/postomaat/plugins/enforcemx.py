# -*- coding: UTF-8 -*-

"""
This plugin allows you to configure from which hosts you 
are willing to accept mail for a given domain.

Check by recipient domain (MX Rules):
This can be useful if you provide shared hosting (= many domains on one mail 
server) and some of the domains use a cloud based spam filter (= MX records 
not pointing directly to your hosting server). You can reject mail coming 
from unexpected hosts trying to bypass the spam filter. 

Check by sender domain (SPF Rules):
Some domains/freemailers do not have an SPF record, although their 
domains are frequently forged and abused as spam sender. 
This plugin allows you to build your own fake SPF database.  
"""

__version__ = "0.0.4"

import os
import re

try:
    from netaddr import IPAddress, IPNetwork
    HAVE_NETADDR = True
except ImportError:
    IPAddress = IPNetwork = None
    HAVE_NETADDR = False

from postomaat.shared import ScannerPlugin, DUNNO, DEFER_IF_PERMIT, REJECT, strip_address, extract_domain, FileList
        
        
class RulesCache(FileList):
    def __init__(self, filename=None, strip=True, skip_empty=True, skip_comments=True, lowercase=False,
                 additional_filters=None, minimum_time_between_reloads=5):
        self.addresses = {}
        self.names = {}
        FileList.__init__(self, filename, strip, skip_empty, skip_comments, lowercase, additional_filters, minimum_time_between_reloads)
             
        
    def _reallyloadData(self, filename):
        regex_ip = '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?|[a-f0-9:]{3,39})$'
        with open(filename) as fp:
            lines = fp.readlines()
        for line in lines:
            line.strip()
            if line and not line.startswith('#'):
                data = line.split(None, 1)
                
                if len(data) != 2:
                    continue
                    
                domain = data[0]
                nets = data[1]
                
                for item in nets.split(','):
                    item = item.strip().lower()
                    if re.match(regex_ip, item):
                        if not domain in self.addresses:
                            self.addresses[domain] = []
                        
                        item = IPNetwork(item)
                        if not item in self.addresses[domain]:
                            self.addresses[domain].append(item)
                    else:
                        if not domain in self.names:
                            self.names[domain] = []
                        if not item in self.names[domain]:
                            self.names[domain].append(item)
    
    
    def _permitted_ip(self, domain, ip):
        if domain not in self.addresses:
            return True
        
        perm = False
        for net in self.addresses[domain]:
            if IPAddress(ip) in net:
                perm = True
                break
        return perm
    
    def _permitted_name(self, domain, hostname):
        if domain not in self.names:
            return True
        
        perm = False
        for name in self.names[domain]:
            if name.endswith(hostname):
                perm = True
                break
        return perm
    
    def permitted(self, domain, ip, hostname):
        self._reload_if_necessary()
        
        #domain is not listed, we accept mail from everywhere
        if not domain in self.addresses and not domain in self.names:
            return True
        
        ip_perm = self._permitted_ip(domain, ip)
        name_perm = self._permitted_name(domain, hostname)
        
        return ip_perm and name_perm
                    


class EnforceMX(ScannerPlugin):
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.mxrules = None
        self.spfrules = None
        
        self.requiredvars={
            'datafile_mx':{
                'default':'/etc/postomaat/conf.d/enforcemx.txt',
                'description':'recipient domain based rule file',
            },
            'datafile_spf':{
                'default':'/etc/postomaat/conf.d/fakespf.txt',
                'description':'sender domain based rule file',
            },
        }
        
        
        
    def examine(self,suspect):
        if not HAVE_NETADDR:
            return DUNNO,None
        
        client_address=suspect.get_value('client_address')
        if client_address is None:
            self.logger.error('No client address found - skipping')
            return DUNNO
        
        client_name=suspect.get_value('client_name')
        if client_name is None:
            client_name = 'unknown'
        
        action, message = self._examine_mx(suspect, client_address, client_name)
        if action == DUNNO:
            action, message = self._examine_spf(suspect, client_address, client_name)
        
        return action, message
    
    
    
    def _examine_mx(self, suspect, client_address, client_name):
        to_address=suspect.get_value('recipient')
        if to_address is None:
            self.logger.warning('No RCPT address found')
            return DEFER_IF_PERMIT,'internal policy error (no rcpt address)'
        
        to_address=strip_address(to_address)
        to_domain=extract_domain(to_address)
        
        if not self.mxrules:
            datafile = self.config.get('EnforceMX','datafile_mx')
            if os.path.exists(datafile):
                self.mxrules = RulesCache(datafile)
            else:
                return DUNNO,None
        
        action = DUNNO
        message = None 
        if not self.mxrules.permitted(to_domain, client_address, client_name):
            action = REJECT
            message = 'We do not accept mail for %s from %s. Please send to MX records!' % (to_domain, client_address)
        
        return action, message
            
            
            
    def _examine_spf(self, suspect, client_address, client_name):
        from_address=suspect.get_value('sender')
        if from_address is None:
            self.logger.warning('No FROM address found')
            return DEFER_IF_PERMIT,'internal policy error (no from address)'
        
        from_address=strip_address(from_address)
        from_domain=extract_domain(from_address)
        
        if not self.spfrules:
            datafile = self.config.get('EnforceMX', 'datafile_spf')
            if os.path.exists(datafile):
                self.spfrules = RulesCache(datafile)
            else:
                return DUNNO,None
            
        action = DUNNO
        message = None 
        if not self.spfrules.permitted(from_domain, client_address, client_name):
            action = REJECT
            message = 'We do not accept mail for %s from %s with name %s. Please use the official mail servers!' % (from_domain, client_address, client_name)
            
        return action, message
    
    
    
    def lint(self):
        lint_ok = True
        
        if not HAVE_NETADDR:
            print('netaddr python module not available - please install')
            lint_ok =  False
        
        if not self.checkConfig():
            print('Error checking config')
            lint_ok = False
        
        datafile = self.config.get('EnforceMX', 'datafile_mx')
        if not os.path.exists(datafile):
            print('MX datafile not found - this plugin will not enforce MX usage')
            lint_ok = False
            
        datafile = self.config.get('EnforceMX', 'datafile_spf')
        if not os.path.exists(datafile):
            print('SPF datafile not found - this plugin will not check fake SPF')
            lint_ok = False
        
        return lint_ok
        
    
    
    def __str__(self):
        return "EnforceMX"
    