"""
plugins with rdns checks
"""
from postomaat.shared import ScannerPlugin,DUNNO,REJECT,DEFER,DEFER_IF_PERMIT,FILTER,HOLD,PREPEND,WARN,FileList
import re

class IdentityCrisis(ScannerPlugin):
    """ Reject clients with no FCcdns and address literal HELO """
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.requiredvars={
            'action':{
                'default':'DEFER',
                'description':'Action if sender has no FcRDNS and is using a address literal HELO',
            },
            'message':{
                'default':'No FcrDNS and address literal HELO - Who are you?',
            },
        }
        self.pattern=re.compile('^\[[0-9a-fA-F:.]+\]$')
        
    def examine(self,suspect):
        retaction=DUNNO
        retmessage=""
 
        revclient=suspect.get_value('reverse_client_name')
        if revclient is None or revclient.strip()=='unknown' or revclient.strip()=='':
            helo_name=suspect.get_value('helo_name')
            if helo_name is None or self.pattern.match(helo_name) is not None:
                retaction=self.config.get(self.section,'action').strip()
                retmessage=self.config.get(self.section,'message').strip()
                
        return retaction,retmessage

    def lint(self):
        lint_ok=True
        retaction=self.config.get(self.section,'action').strip().lower()
        reasonable_actions=[REJECT,DEFER,DEFER_IF_PERMIT,FILTER,HOLD,PREPEND,WARN]
        if retaction not in reasonable_actions:
            print "are you sure about action '%s' ?"%retaction
            print "I'd expect one of %s"%(",".join(reasonable_actions))
            lint_ok=False
        
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
        
        return lint_ok
                        
    def __str__(self):
        return "Identity Crisis"

class CreativeTLD(ScannerPlugin):
    """ Reject clients with unofficial TLD in rdns """
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.requiredvars={
            'action':{
                'default':'REJECT',
                'description':'Action if sender uses invalid TLD',
            },
            'message':{
                'default':'forged rDNS TLD',
            },
            'tldfile':{
                'default':'/etc/mail/tlds-alpha-by-domain.txt',
            },
        }

        self.filelist=FileList(filename=None,strip=True, skip_empty=True, skip_comments=True,lowercase=True,minimum_time_between_reloads=86400)

    def examine(self,suspect):
        retaction,retmessage = DUNNO,''
        revclient=suspect.get_value('reverse_client_name')
        self.filelist.filename=self.config.get(self.section,'domainsfile')
        tlds = self.filelist.get_list()

        if revclient is None or revclient.strip()=='unknown' or '.' not in revclient:
            return DUNNO,''

        tld=revclient.split('.')[-1].lower()
        if tld not in tlds:
            retaction=self.config.get(self.section,'action').strip()
            retmessage=self.config.get(self.section,'message').strip()

        return retaction,retmessage

    def lint(self):
        lint_ok=True
        retaction=self.config.get(self.section,'action').strip().lower()
        reasonable_actions=[REJECT,DEFER,DEFER_IF_PERMIT,FILTER,HOLD,PREPEND,WARN]
        if retaction not in reasonable_actions:
            print "are you sure about action '%s' ?"%retaction
            print "I'd expect one of %s"%(",".join(reasonable_actions))
            lint_ok=False

        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False

        return lint_ok

    def __str__(self):
        return "Creative TLD"
