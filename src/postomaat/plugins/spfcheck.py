# -*- coding: UTF-8 -*-

from postomaat.shared import ScannerPlugin, DUNNO, REJECT, DEFER_IF_PERMIT, strip_address, extract_domain
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
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.requiredvars={
            'ip_whitelist':{
                'default':'127.0.0.0/8',
                'description':'which sending hosts/networks should be excluded from SPF checks',
            },
            'domain_whitelist':{
                'default':'',
                'description':'which sender domains should be excluded from SPF checks',
            },
            'on_softfail':{
                'default':'DUNNO',
                'description':'what to do on softfail',
            },
            'on_softerror':{
                'default':'DEFER',
                'description':'what to do on softerror',
            },
        }
        
        
        
    def examine(self,suspect):
        if not have_spf:
            return DUNNO
        
        client_address=suspect.get_value('client_address')
        if client_address is None:
            self.logger.info('No client address found')
            return DUNNO
        if have_netaddr:
            ip_whitelist=self.config.get('SPFPlugin','ip_whitelist')
            ip_whitelist=[IPNetwork(i.strip()) for i in ip_whitelist.split(',')]
            for net in ip_whitelist:
                if IPAddress(client_address) in net:
                    return DUNNO
        
        sender=suspect.get_value('sender')
        if sender is None:
            self.logger.warning('No RCPT address found')
            return DEFER_IF_PERMIT,'internal policy error (no from address)'
        sender_email = strip_address(sender)
        try:
            sender_domain = extract_domain(sender_email)
        except ValueError as e:
            self.logger.warning(str(e))
            return DUNNO
            
        domain_whitelist=self.config.get('SPFPlugin','domain_whitelist')
        domain_whitelist=[i.strip() for i in domain_whitelist.split(',')]
        if sender_domain in domain_whitelist:
            return DUNNO
        
        helo_name=suspect.get_value('helo_name')
        if helo_name is None:
            self.logger.error('No SMTP HELO name found')
            return DUNNO
        
        on_softfail=self.config.get('SPFPlugin','on_softfail')
        softfail = DUNNO
        if on_softfail == 'DEFER':
            softfail =  DEFER_IF_PERMIT
        on_softerror=self.config.get('SPFPlugin','on_softerror')
        softerror = DUNNO
        if on_softerror == 'REJECT':
            softerror = REJECT
        
        result, explanation = spf.check2(client_address, sender_email, helo_name)
        self.logger.debug('Postomaat SPF check: ip: %s, from: %s, helo: %s, result: %s' % (client_address, sender_email, helo_name, result))
        
        action = DUNNO
        message = None
        
        if result == 'fail':
            action = REJECT
            message = explanation
        elif result == 'temperror':
            action = DEFER_IF_PERMIT
            message = explanation
        elif result == 'softfail' and softfail != DUNNO:
            action = softfail
            message = explanation
        elif result == 'softerror' and softerror != DUNNO:
            action = softerror
            message = explanation
        
        return action, message
         
        
    
    def lint(self):
        lint_ok = True
        
        if not have_spf:
            print 'pyspf or pydns module not installed - this plugin will do nothing'
            lint_ok = False
            
        if not have_netaddr:
            print 'netaddr python module not installed - IP whitelist is disabled'
            lint_ok = False
        
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
        
        return lint_ok
        