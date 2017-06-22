# -*- coding: UTF-8 -*-

from postomaat.shared import ScannerPlugin, DUNNO, REJECT, apply_template
try:
    import SRS
    HAVE_SRS=True
except ImportError:
    SRS=None
    HAVE_SRS=False


class SRSBounceVerify(ScannerPlugin):
    """
    This plugin checks the validity of SRS bounces.
    Intended to be used in conjunction with after queue SRS mechanisms such as Fuglu's SRS Plugin.
    """

    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()

        self.requiredvars = {
            'forward_domain': {
                'default': 'example.com',
                'description': 'the SRS envelope sender domain',
            },

            'secret': {
                'default': '',
                'description': 'cryptographic secret. set the same random value on all your machines',
            },

            'maxage': {
                'default': '8',
                'description': 'maximum lifetime of bounces',
            },

            'hashlength': {
                'default': '8',
                'description': 'size of auth code',
            },

            'separator': {
                'default': '=',
                'description': 'SRS token separator',
            },

            'messagetemplate':{
                'default':'${from_address} is not a valid SRS bounce address'
            },

        }
    
    
    
    def _init_srs(self):
        secret = self.config.get(self.section, 'secret')
        maxage = self.config.getint(self.section, 'maxage')
        hashlength = self.config.getint(self.section, 'hashlength')
        separator = self.config.get(self.section, 'separator')
        srs = SRS.new(secret=secret, maxage=maxage, hashlength=hashlength, separator=separator, alwaysrewrite=True)
        return srs
    
        
        
    def examine(self, suspect):
        if not HAVE_SRS:
            return DUNNO
        
        forward_domain = self.config.get(self.section, 'forward_domain')
        if suspect.to_domain != forward_domain:
            self.logger.debug('SRS: ignoring mail to %s - only accepting %s' % (suspect.to_address, forward_domain))
            return DUNNO
        
        action = DUNNO
        message = None
        
        srs = self._init_srs()
        if suspect.to_address.lower().startswith('srs'):
            orig_rcpt = suspect.to_address
            try:
                recipient = srs.reverse(orig_rcpt)
                self.logger.info('SRS: decrypted bounce address %s to %s' % (orig_rcpt, recipient))
            except Exception as e:
                self.logger.error('SRS: Failed to decrypt %s reason: %s' % (orig_rcpt, str(e)))
                action = REJECT
                message = apply_template(self.config.get(self.section, 'messagetemplate'), suspect)
        else:
            self.logger.debug('SRS: ignoring unsigned address %s' % (suspect.to_address))
                
        return action, message
        
        
        
    def lint(self):
        allok = self.checkConfig()
        if not HAVE_SRS:
            allok = False
            print 'SRS library not found'
            
        if self.config.get(self.section, 'secret') == '':
            allok = False
            print 'no secret set in config'
        
        if allok:
            srs = self._init_srs()
            forward_domain = self.config.get(self.section, 'forward_domain')
            srs.forward('foobar@example.com', forward_domain)
            
        return allok
    
    
    
    def __str__(self):
        return "SRSBounceVerify"
    
    
    