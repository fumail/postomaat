# -*- coding: UTF-8 -*-

from postomaat.shared import ScannerPlugin, DUNNO, strip_address, extract_domain, apply_template
from postomaat.filetools import ListConfigFile
try:
    import spf
    have_spf = True
except:
    have_spf = False
    
try:
    from netaddr import IPAddress, IPNetwork
    have_netaddr = True
except:
    have_netaddr = False
    

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
            return DUNNO

        #check ip whitelist
        ip_whitelist_file=self.config.get(self.section,'ip_whitelist_file')
        if ip_whitelist_file!=None:
            if self.ip_whitelist_loader==None:
                self.ip_whitelist_loader=ListConfigFile(ip_whitelist_file,lowercase=True)

            if self.ip_whitelist_loader.file_changed():
                plainlist=self.ip_whitelist_loader.get_content()

                if have_netaddr:
                    self.ip_whitelist=[IPNetwork(x) for x in plainlist]
                else:
                    self.ip_whitelist=plainlist
            if have_netaddr:
                checkaddr=IPAddress(addr)
                for net in self.ip_whitelist:
                        if checkaddr in net:
                            return True
            else:
                if addr in plainlist:
                        return True
        return False


    def examine(self,suspect):
        if not have_spf:
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
        if sender_email=='' or sender_email==None:
            return DUNNO

        selective_sender_domain_file=self.config.get(self.section,'domain_selective_spf_file')
        if selective_sender_domain_file!='':
            if self.selective_domain_loader==None:
                self.selective_domain_loader=ListConfigFile(selective_sender_domain_file,lowercase=True)
            try:
                sender_domain = extract_domain(sender_email)
                if sender_domain==None:
                    return DUNNO
            except ValueError as e:
                self.logger.warning(str(e))
                return DUNNO
            if not sender_domain.lower() in self.selective_domain_loader.get_content():
                return DUNNO

        result, explanation = spf.check2(client_address, sender_email, helo_name)
        suspect.tags['spf']=result
        if result!='none':
            self.logger.info('SPF client=%s, sender=%s, h=%s result=%s : %s' % (client_address, sender_email, helo_name, result,explanation))
        
        action = DUNNO
        message = apply_template(self.config.get(self.section,'messagetemplate'),suspect,dict(result=result,explanation=explanation))

        configopt='on_%s'%result
        if self.config.has_option(self.section,configopt):
            action=self.config.get(self.section,configopt)
        else:
            action=DUNNO

        return action, message
         
        
    
    def lint(self):
        lint_ok = True
        
        if not have_spf:
            print 'pyspf or pydns module not installed - this plugin will do nothing'
            lint_ok = False
            
        if not have_netaddr:
            print 'WARNING: netaddr python module not installed - IP whitelist will not support CIDR notation'

        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
        
        return lint_ok

    def __str__(self):
        return "SPF"