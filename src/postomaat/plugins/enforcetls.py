# -*- coding: UTF-8 -*-

from postomaat.shared import ScannerPlugin, DUNNO, strip_address, extract_domain, apply_template, FileList, string_to_actioncode



class EnforceTLS(ScannerPlugin):
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.selective_domain_loader = None
        
        self.requiredvars={
            'domain_selective_tls_file':{
                'default':'',
                'description':'if this is non-empty, only recipient domains in this file will be forced to use TLS',
            },
            'action':{
                'default':'DEFER',
                'description':'Action if connection is not TLS encrypted. set to DUNNO, DEFER, REJECT',
            },
            'messagetemplate':{
                'default':'Unencrypted connection. This recipient requires TLS'
            }
        }
    
    
    
    def examine(self, suspect):
        encryption_protocol = suspect.get_value('encryption_protocol')
        recipient=suspect.get_value('recipient')
        
        rcpt_email = strip_address(recipient)
        if rcpt_email=='' or rcpt_email is None:
            return DUNNO
        
        selective_rcpt_domain_file=self.config.get(self.section,'domain_selective_tls_file')
        if selective_rcpt_domain_file!='':
            if self.selective_domain_loader is None:
                self.selective_domain_loader=FileList(selective_rcpt_domain_file,lowercase=True)
            try:
                sender_domain = extract_domain(rcpt_email)
                if sender_domain is None:
                    return DUNNO
            except ValueError as e:
                self.logger.warning(str(e))
                return DUNNO
            if not sender_domain.lower() in self.selective_domain_loader.get_list():
                return DUNNO
            
        action = DUNNO
        message = apply_template(self.config.get(self.section,'messagetemplate'),suspect)

        if encryption_protocol == '':
            action=string_to_actioncode(self.config.get(self.section, 'action'))
            
        return action, message
    
    
    
    def lint(self):
        lint_ok = True
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
        
        return lint_ok
    
    
    
    def __str__(self):
        return "EnforceTLS"