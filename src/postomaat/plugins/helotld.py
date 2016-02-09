# -*- coding: UTF-8 -*-

from postomaat.shared import ScannerPlugin, DUNNO,apply_template
from postomaat.filetools import ListConfigFile
import os

class HELOTLDPlugin(ScannerPlugin):
    """
    This plugin rejects messages if the HELO uses an invalid TLD
    """
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.requiredvars={
            'tldfile':{
                'default':'/etc/mail/tlds-alpha-by-domain.txt',
                'description':'filename containing official TLDs. Add a cronjob to dowload this.',
            },
            'exceptionfile':{
                'default':'/etc/mail/tlds-exceptions.txt',
                'description':'additional tld file with local exceptions',
            },
            'on_fail':{
                'default':'REJECT',
                'description':'Action to take if the TLD is invalid',
            },
            'messagetemplate':{
                'default':"""HELO ${helo_name} contains forged/unresolvable TLD '.${helo_tld}'"""
            }
        }
        
        self.tld_loader=None
        self.exception_loader=None



    def examine(self,suspect):

        helo_name=suspect.get_value('helo_name')

        if helo_name is None :
            self.logger.error('missing helo')
            return DUNNO

        helo_tld=helo_name.split('.')[-1].lower()

        #initialize loaders
        tld_file=self.config.get(self.section,'tldfile')
        if self.tld_loader==None:
            self.tld_loader=ListConfigFile(tld_file,lowercase=True,reload_after=3600)

        if helo_tld in self.tld_loader.get_content():
            return DUNNO,''

        exceptionfile=self.config.get(self.section,'exceptionfile')
        if self.exception_loader==None:
            self.exception_loader=ListConfigFile(exceptionfile,lowercase=True,reload_after=10)

        if helo_tld in self.exception_loader.get_content():
            return DUNNO,''

        message = apply_template(self.config.get(self.section,'messagetemplate'),suspect,dict(helo_tld=helo_tld))
        action=self.config.get(self.section,"on_fail")

        return action, message

    def lint(self):
        lint_ok = True
        tld_file=self.config.get(self.section,'tldfile')
        exceptionfile=self.config.get(self.section,'exceptionfile')
        if not os.path.exists(tld_file):
            print "TLD file %s not found"%tld_file
            lint_ok = False
        if not os.path.exists(exceptionfile):
            print "TLD exception file %s not found"%exceptionfile
            lint_ok = False

        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False

        return lint_ok

    def __str__(self):
        return "HeloTLD"