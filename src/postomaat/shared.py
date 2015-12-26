#   Copyright 2012 Oli Schacher
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

import logging
import time
import socket
import random
import ConfigParser
import os
import datetime
from string import Template

#answers
REJECT="reject"
DEFER="defer"
DEFER_IF_REJECT="defer_if_reject"
DEFER_IF_PERMIT="defer_if_permit"
ACCEPT="ok"
OK="ok" #same as ACCEPT
DUNNO="dunno"
DISCARD="discard"
FILTER="filter"
HOLD="hold"
PREPEND="prepend"
REDIRECT="redirect"
WARN="warn"

#protocol stages
CONNECT="CONNECT"
EHLO="EHLO"
HELO="HELO", 
MAIL="MAIL" 
RCPT="RCPT"
DATA="DATA"
END_OF_MESSAGE="END-OF-MESSAGE"
VRFY="VRFY"
ETRN="ETRN"
PERMIT="PERMIT"

HOSTNAME=socket.gethostname()

def apply_template(templatecontent,suspect,values=None,valuesfunction=None):
    """Replace templatecontent variables 
    with actual values from suspect
    the calling function can pass additional values by passing a values dict
    
    if valuesfunction is not none, it is called with the final dict with all built-in and passed values
    and allows further modifications, like SQL escaping etc
    """
    if values==None:
        values={}
        
    values = dict(suspect.values.items()+values.items())
    values['timestamp']=int(time.time())
    values['from_address']=suspect.from_address
    values['to_address']=suspect.to_address
    values['from_domain']=suspect.from_domain
    values['to_domain']=suspect.to_domain
    values['date']=str(datetime.date.today())
    values['time']=time.strftime('%X')        
    
    if valuesfunction!=None:
        values=valuesfunction(values)
    else:
        #replace None with empty string
        for k,v in values.iteritems():
            if v==None:
                values[k]=''
    
    template = Template(templatecontent)
    message= template.safe_substitute(values)
    return message

class Suspect(object):
    """
    The suspect represents the message to be scanned. Each scannerplugin will be presented
    with a suspect and may modify the tags
    """
    
    def __init__(self,values):
        self.values=values
        #all values offered by postfix (dict)
        
        self.tags={}
        #tags set by plugins
        self.tags['decisions']=[]
        
        #additional basic information
        self.timestamp=time.time()

    def get_value(self,key):
        """returns one of the postfix supplied values"""
        if not self.values.has_key(key):
            return None
        return self.values[key] 
    
    def get_stage(self):
        """backwards compatibility alias for get_protocol_state"""
        return self.get_protocol_state()

    def get_protocol_state(self):
        """returns the current protocol state"""
        return self.get_value('protocol_state')
          
    def get_tag(self,key):
        """returns the tag value"""
        if not self.tags.has_key(key):
            return None
        return self.tags[key]

    def __str__(self):
        return "Suspect:sender=%s recipient=%s tags=%s"%(self.from_address, self.to_address, self.tags)
    
    @property
    def from_address(self):
        sender=self.get_value('sender')
        if sender==None:
            return None
        
        try:
            addr=strip_address(sender)
            return addr
        except:
            return None
    
    @property
    def from_domain(self):
        from_address=self.from_address
        if from_address==None:
            return None
        
        try:
            return extract_domain(from_address)
        except:
            return None
        
    @property
    def to_address(self):
        rec=self.get_value('recipient')
        if rec==None:
            return None
        
        try:
            addr=strip_address(rec)
            return addr
        except:
            return None
    
    @property
    def to_domain(self):
        rec=self.to_address
        if rec==None:
            return None
        try:
            return extract_domain(rec)
        except:
            return None
    

        
##it is important that this class explicitly extends from object, or __subclasses__() will not work!
class BasicPlugin(object):
    """Base class for all plugins"""
    
    def __init__(self,config,section=None):
        if section==None:
            self.section=self.__class__.__name__
        else:
            self.section=section
        self.config=config
        self.requiredvars=()
    
    def _logger(self):
        """returns the logger for this plugin"""
        myclass=self.__class__.__name__
        loggername="postomaat.plugin.%s"%(myclass)
        return logging.getLogger(loggername)
    
    def lint(self):
        return self.checkConfig()
    
    def checkConfig(self):
        allOK=True
        
        #old config style
        if type(self.requiredvars)==tuple or type(self.requiredvars)==list:
            for configvar in self.requiredvars:
                if type(self.requiredvars)==tuple:
                    (section,config)=configvar
                else:
                    config=configvar
                    section=self.section                   
                try:
                    var=self.config.get(section,config)
                except ConfigParser.NoOptionError:
                    print "Missing configuration value [%s] :: %s"%(section,config)
                    allOK=False
                except ConfigParser.NoSectionError:
                    print "Missing configuration section %s"%(section)
                    allOK=False    
        
        #new config style
        if type(self.requiredvars)==dict:
            for config,infodic in self.requiredvars.iteritems():
                section=self.section
                if 'section' in infodic:
                    section=infodic['section']
                    
                try:
                    var=self.config.get(section,config)
                    if 'validator' in infodic:
                        if not infodic["validator"](var):
                            print "Validation failed for [%s] :: %s"%(section,config)
                            allOK=False          
                except ConfigParser.NoSectionError:
                    print "Missing configuration section [%s] :: %s"%(section,config)
                    allOK=False
                except ConfigParser.NoOptionError:
                    print "Missing configuration value [%s] :: %s"%(section,config)
                    allOK=False
        
        return allOK


def strip_address(address):                    
        """                                          
        Strip the leading & trailing <> from an address.  Handy for
        getting FROM: addresses.                                   
        """                                                        
        start = address.find('<') + 1                              
        if start<1:                                                
            start=address.find(':')+1                              
        if start<1:                                                
            return address
        end = address.find('>')                                    
        if end<0:
            end=len(address)                                        
        retaddr=address[start:end]                                 
        retaddr=retaddr.strip()                                    
        return retaddr 

def extract_domain(address):
    if address==None or address=='':
        return None
    else:                                                        
        try:                                                   
            (user, domain) = address.rsplit('@',1)                
            return domain                                      
        except Exception, e:                                   
            raise ValueError,"invalid email address: '%s'"%address

class ScannerPlugin(BasicPlugin):
    """Scanner Plugin Base Class"""
    def examine(self,suspect):
        self._logger().warning('Unimplemented examine() method')

    #legacy...
    def stripAddress(self,address):
        return strip_address(address)

    def extractDomain(self,address):
        return extract_domain(address)
        
            
def get_config(postomaatconfigfile=None,dconfdir=None):
    newconfig=ConfigParser.ConfigParser()
    logger=logging.getLogger('postomaat.shared')
    
    if postomaatconfigfile==None:
        postomaatconfigfile='/etc/postomaat/postomaat.conf'
    
    if dconfdir==None:
        dconfdir='/etc/postomaat/conf.d'
    
    newconfig.readfp(open(postomaatconfigfile))
    
    #load conf.d
    if os.path.isdir(dconfdir):
        filelist=os.listdir(dconfdir)
        configfiles=[dconfdir+'/'+c for c in filelist if c.endswith('.conf')]
        logger.debug('Conffiles in %s: %s'%(dconfdir,configfiles))
        readfiles=newconfig.read(configfiles)
        logger.debug('Read additional files: %s'%(readfiles))
    return newconfig


class FileList(object):

    """Map all lines from a textfile into a list. If the file is changed, the list is refreshed automatically
    Each line can be run through a callback filter which can change or remove the content.

    filename: The textfile which should be mapped to a list. This can be changed at runtime. If None, an empty list will be returned.
    strip: remove leading/trailing whitespace from each line. Note that the newline character is always stripped
    skip_empty: skip empty lines (if used in combination with strip: skip all lines with only whitespace)
    skip_comments: skip lines starting with #
    lowercase: lowercase each line
    additional_filters: function or list of functions which will be called for each line on reload.
        Each function accept a single argument and must return a (possibly modified) line or None to skip this line
    minimum_time_between_reloads: number of seconds to cache the list before it will be reloaded if the file changes
    """

    def __init__(self, filename=None, strip=True, skip_empty=True, skip_comments=True, lowercase=False, additional_filters=None, minimum_time_between_reloads=5):
        self.filename = filename
        self.minium_time_between_reloads = minimum_time_between_reloads
        self._lastreload = 0
        self.linefilters = []
        self.content = []
        self.logger = logging.getLogger('filelist')

        # we always strip newline
        self.linefilters.append(lambda x: x.rstrip('\r\n'))

        if strip:
            self.linefilters.append(lambda x: x.strip())

        if skip_empty:
            self.linefilters.append(lambda x: x if x != '' else None)

        if skip_comments:
            self.linefilters.append(
                lambda x: None if x.strip().startswith('#') else x)

        if lowercase:
            self.linefilters.append(lambda x: x.lower())

        if filename != None:
            self._reload_if_necessary()

    def _reload_if_necessary(self):
        """Calls _reload if the file has been changed since the last reload"""
        now = time.time()
        # check if reloadinterval has passed
        if now - self._lastreload < self.minium_time_between_reloads:
            return
        if self.file_changed():
            self._reload()

    def _reload(self):
        """Reload the file and build the list"""
        self.logger.info('Reloading file %s' % self.filename)
        statinfo = os.stat(self.filename)
        ctime = statinfo.st_ctime
        self._lastreload = ctime
        fp = open(self.filename, 'r')
        lines = fp.readlines()
        fp.close()
        newcontent = []

        for line in lines:
            for func in self.linefilters:
                line = func(line)
                if line == None:
                    break

            if line != None:
                newcontent.append(line)

        self.content = newcontent

    def file_changed(self):
        """Return True if the file has changed on disks since the last reload"""
        if not os.path.isfile(self.filename):
            return False
        statinfo = os.stat(self.filename)
        ctime = statinfo.st_ctime
        if ctime > self._lastreload:
            return True
        return False

    def get_list(self):
        """Returns the current list. If the file has been changed since the last call, it will rebuild the list automatically."""
        self._reload_if_necessary()
        return self.content
