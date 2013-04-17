"""
plugins with rdns checks
"""
from postomaat.shared import ScannerPlugin,DUNNO
import re

class IdentityCrisis(ScannerPlugin):
    """ Reject clients with no FCcdns and address literal HELO """
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.requiredvars={
            'action':{
                'default':'DEFER',
                'description':'Action if sender has no FcRDNS and is using a address literal helo',
            },
            'message':{
                'default':'No FcrDNS and address literal HELO - who are you?',
            }
        }
        self.pattern=re.compile('^\[[0-9a-fA-F:.]+\]$')
        
    def examine(self,suspect):
        retaction=DUNNO
        retmessage=""

        revclient=suspect.get_value('reverse_client_name')
        if revclient==None or revclient.strip()=='unknown' or revclient.strip()=='':
            helo_name=suspect.get_value('helo_name')
            if helo_name==None or self.pattern.match(helo_name)!=None:
                retaction=self.config.get(self.section,'action')
                retmessage=self.config.get(self.section,'message')
                
        return retaction,retmessage
    
