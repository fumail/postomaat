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
import os
import datetime
import threading
from string import Template
try:
    import configparser
except ImportError:
    import ConfigParser as configparser



HOSTNAME=socket.gethostname()



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

ALLCODES = {
    "reject":REJECT,
    "defer":DEFER,
    "defer_if_reject":DEFER_IF_REJECT,
    "defer_if_permit":DEFER_IF_PERMIT,
    "ok":OK,
    "dunno":DUNNO,
    "discard":DISCARD,
    "filter":FILTER,
    "hold":HOLD,
    "prepend":PREPEND,
    "redirect":REDIRECT,
    "warn":WARN,
}


#protocol stages
CONNECT="CONNECT"
EHLO="EHLO"
HELO="HELO"
MAIL="MAIL"
RCPT="RCPT"
DATA="DATA"
END_OF_MESSAGE="END-OF-MESSAGE"
VRFY="VRFY"
ETRN="ETRN"
PERMIT="PERMIT"

ALLSTAGES = {
    "CONNECT":CONNECT,
    "EHLO":EHLO,
    "HELO":HELO,
    "MAIL":MAIL,
    "RCPT":RCPT,
    "DATA":DATA,
    "END-OF-MESSAGE":END_OF_MESSAGE,
    "VRFY":VRFY,
    "ETRN":ETRN,
    "PERMIT":PERMIT,
}



def actioncode_to_string(actioncode):
    """Return the human readable string for this code"""
    for key, val in list(ALLCODES.items()):
        if val == actioncode:
            return key
    if actioncode == ACCEPT: #alias for OK
        return ACCEPT
    if actioncode is None:
        return "NULL ACTION CODE"
    return 'INVALID ACTION CODE %s' % actioncode



def string_to_actioncode(actionstring):
    """return the code for this action"""
    alower = actionstring.lower().strip()
    return ALLCODES[alower]



def stage_to_string(stagename):
    """Return the human readable string for this code"""
    for key, val in list(ALLSTAGES.items()):
        if val == stagename:
            return key
    if stagename is None:
        return "NULL STAGE"
    return 'INVALID STAGE %s' % stagename



def string_to_stage(stagestring):
    """return the code for this action"""
    alower = stagestring.lower().strip()
    return ALLSTAGES[alower]



def apply_template(templatecontent,suspect,values=None,valuesfunction=None):
    """Replace templatecontent variables 
    with actual values from suspect
    the calling function can pass additional values by passing a values dict
    
    if valuesfunction is not none, it is called with the final dict with all built-in and passed values
    and allows further modifications, like SQL escaping etc
    """
    if values is None:
        values={}
        
    values = default_template_values(suspect, values)
    
    if valuesfunction is not None:
        values=valuesfunction(values)
    else:
        #replace None with empty string
        for k,v in values.iteritems():
            if v is None:
                values[k]=''
    
    template = Template(templatecontent)
    message= template.safe_substitute(values)
    return message


def default_template_values(suspect, values=None):
    """Return a dict with default template variables applicable for this suspect
    if values is not none, fill the values dict instead of returning a new one"""

    if values is None:
        values = {}
        
    values = dict(suspect.values.items()+values.items())
    values['timestamp']=int(time.time())
    values['from_address']=suspect.from_address
    values['to_address']=suspect.to_address
    values['from_domain']=suspect.from_domain
    values['to_domain']=suspect.to_domain
    values['date']=str(datetime.date.today())
    values['time']=time.strftime('%X')
    return values



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
        if sender is None:
            return None
        
        try:
            addr=strip_address(sender)
            return addr
        except Exception:
            return None
    
    @property
    def from_domain(self):
        from_address=self.from_address
        if from_address is None:
            return None
        
        try:
            return extract_domain(from_address)
        except ValueError:
            return None
        
    @property
    def to_address(self):
        rec=self.get_value('recipient')
        if rec is None:
            return None
        
        try:
            addr=strip_address(rec)
            return addr
        except Exception:
            return None
    
    @property
    def to_domain(self):
        rec=self.to_address
        if rec is None:
            return None
        try:
            return extract_domain(rec)
        except ValueError:
            return None
    

        
##it is important that this class explicitly extends from object, or __subclasses__() will not work!
class BasicPlugin(object):
    """Base class for all plugins"""
    
    def __init__(self,config,section=None):
        if section is None:
            self.section=self.__class__.__name__
        else:
            self.section=section
        self.config=config
        self.requiredvars=()
    
    def _logger(self):
        """returns the logger for this plugin"""
        myclass=self.__class__.__name__
        loggername="postomaat.plugin.%s" % myclass
        return logging.getLogger(loggername)
    
    def lint(self):
        return self.check_config()

    def checkConfig(self):
        """old name for check_config"""
        return self.check_config()
    
    def check_config(self):
        """Print missing / non-default configuration settings"""
        allOK = True

        # old config style
        if type(self.requiredvars) == tuple or type(self.requiredvars) == list:
            for configvar in self.requiredvars:
                if type(self.requiredvars) == tuple:
                    (section, config) = configvar
                else:
                    config = configvar
                    section = self.section
                try:
                    var = self.config.get(section, config)
                except configparser.NoOptionError:
                    print("Missing configuration value [%s] :: %s" % (
                        section, config))
                    allOK = False
                except configparser.NoSectionError:
                    print("Missing configuration section %s" % (section))
                    allOK = False

        # new config style
        if type(self.requiredvars) == dict:
            for config, infodic in self.requiredvars.items():
                section = self.section
                if 'section' in infodic:
                    section = infodic['section']

                try:
                    var = self.config.get(section, config)
                    if 'validator' in infodic:
                        if not infodic["validator"](var):
                            print("Validation failed for [%s] :: %s" % (
                                section, config))
                            allOK = False
                except configparser.NoSectionError:
                    print("Missing configuration section [%s] :: %s" % (
                        section, config))
                    allOK = False
                except configparser.NoOptionError:
                    print("Missing configuration value [%s] :: %s" % (
                        section, config))
                    allOK = False

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

def extract_domain(address, lowercase=True):
    if address is None or address=='':
        return None
    else:                                                        
        try:                                                   
            user, domain = address.rsplit('@',1)
            if lowercase:
                domain = domain.lower()
            return domain                                      
        except Exception as e:
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
    newconfig=configparser.ConfigParser()
    logger=logging.getLogger('postomaat.shared')
    
    if postomaatconfigfile is None:
        postomaatconfigfile='/etc/postomaat/postomaat.conf'
    
    if dconfdir is None:
        dconfdir='/etc/postomaat/conf.d'

    with open(postomaatconfigfile) as fp:
        newconfig.readfp(fp)
    
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
        self.logger = logging.getLogger('postomaat.filelist')

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

        if additional_filters is not None:
            if type(additional_filters) == list:
                self.linefilters.extend(additional_filters)
            else:
                self.linefilters.append(additional_filters)

        if filename is not None:
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
        with open(self.filename, 'r') as fp:
            lines = fp.readlines()
        newcontent = []

        for line in lines:
            for func in self.linefilters:
                line = func(line)
                if line is None:
                    break

            if line is not None:
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



class SettingsCache(object):
    def __init__(self, cachetime=30, cleanupinterval=300):
        self.cache={}
        self.cachetime=cachetime
        self.cleanupinterval=cleanupinterval
        self.lock=threading.Lock()
        self.logger=logging.getLogger("postomaat.settingscache")
        
        t = threading.Thread(target=self.clear_cache_thread)
        t.daemon = True
        t.start()
        
    def put_cache(self,key,obj):
        gotlock=self.lock.acquire(True)
        if gotlock:
            self.cache[key]=(obj,time.time())
            self.lock.release()
        
    def get_cache(self,key):
        gotlock=self.lock.acquire(True)
        if not gotlock:
            return None
        
        ret=None
        
        if key in self.cache:
            obj,instime=self.cache[key]
            now=time.time()
            if now-instime<self.cachetime:
                ret=obj
            else:
                del self.cache[key]
                
        self.lock.release()
        return ret
    
    def clear_cache_thread(self):
        while True:
            time.sleep(self.cleanupinterval)
            now=time.time()
            gotlock=self.lock.acquire(True)
            if not gotlock:
                continue
            
            cleancount=0
            
            for key in self.cache.keys()[:]:
                obj,instime=self.cache[key]
                if now-instime>self.cachetime:
                    del self.cache[key]
                    cleancount+=1
            self.lock.release()
            self.logger.debug("Cleaned %s expired entries."%cleancount)