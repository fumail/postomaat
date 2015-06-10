#   Copyright 2013 Oli Schacher
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
#
#

BASENAME="postomaat" #project name (root logger etc)
CONFDIR="/etc/%s"%BASENAME
import logging
import sys
import os
import thread
import socket
import string
import time
import traceback
import datetime
import unittest
import ConfigParser
import re
import inspect
from postomaat.plugins import *
from postomaat.shared import *
import threading
from threadpool import ThreadPool
import code


HOSTNAME=socket.gethostname()

class SessionHandler(object):
    """thread handling one message"""
    def __init__(self,incomingsocket,config,plugins):
        self.incomingsocket=incomingsocket
        self.logger=logging.getLogger("%s.SessionHandler"%BASENAME)
        self.action=DUNNO
        self.arg=""
        self.config=config
        self.plugins=plugins
        self.workerthread = None

    def set_threadinfo(self, status):
        if self.workerthread != None:
            self.workerthread.threadinfo = status

        
    def handlesession(self, workerthread=None):
        self.workerthread = workerthread
        sess=None
        try:
            self.set_threadinfo('receiving message')
            sess=PolicydSession(self.incomingsocket,self.config)
            success=sess.getrequest()
            if not success:
                self.logger.error('incoming request did not finish')
                sess.closeconn()
            
            values=sess.values
            suspect=Suspect(values)

            #store incoming port to tag, could be used to disable plugins based on port
            try:
                port=sess.socket.getsockname()[1]
                if port is not None:
                    suspect.tags['incomingport']=port
            except Exception,e:
                self.logger.warning('Could not get incoming port: %s'%str(e))
            
            self.set_threadinfo("Handling message %s" % suspect)
            starttime=time.time()
            self.run_plugins(suspect,self.plugins)
             
            #how long did it all take?
            difftime=time.time()-starttime
            suspect.tags['postomaat.scantime']="%.4f"%difftime
            
            #checks done.. print out suspect status
            self.logger.debug(suspect)
            self.set_threadinfo("Finishing message %s" % suspect)
            sess.endsession(self.action,self.arg)
            
        except KeyboardInterrupt:
            sys.exit(0)    
        except Exception, e:
            self.logger.error('Exception: %s'%e)
            if sess!=None:
                sess.closeconn()
        self.logger.debug('Session finished')

    def run_plugins(self,suspect,pluglist):
        """Run scannerplugins on suspect"""
        for plugin in pluglist:
            try:
                self.logger.debug('Running plugin %s'%plugin)
                self.set_threadinfo(
                    "%s : Running Plugin %s" % (suspect, plugin))
                ans = plugin.examine(suspect)
                arg=None
                if type(ans) is tuple:
                    result,arg=ans
                else:
                    result=ans
                
                if result==None:
                    result=DUNNO
                else:
                    result=result.strip().lower()
                self.action=result
                self.arg=arg
                suspect.tags['decisions'].append((str(plugin),result))
                self.logger.debug('Plugin sez: %s (arg=%s)'%(result,arg))
                
                if result!=DUNNO:
                    self.logger.debug('Plugin makes a decision other than DUNNO - not running any other plugins')
                    break
                
            except Exception,e:
                exc=traceback.format_exc()
                self.logger.error('Plugin %s failed: %s'%(str(plugin),exc))
                
   

class MainController(object):
    """main class to startup and control the app"""
    plugins=[]
    config=None
    
    def __init__(self,config):
        
        self.requiredvars={
            #main section
            'identifier':{
              'section':'main',
              'description':"""identifier can be any string that helps you identifying your config file\nthis helps making sure the correct config is loaded. this identifier will be printed out when postomaat is reloading its config""",
              'default':'dist',
            },
                           
            'daemonize':{
              'section':'main',
              'description':"run as a daemon? (fork)",
              'default':"1",
              #todo: validator...?
            },
                           
            'user':{
              'section':'main',
              'description':"run as user",
              'default':"nobody",
              #todo: validator, check user...?
            },  
                           
            'group':{
              'section':'main',
              'description':"run as group",
              'default':"nobody",
              #todo: validator, check user...?
            },   
                           
           'plugindir':{
              'section':'main',
              'description':"where should postomaat search for additional plugins",
              'default':"",
            },
                           
            'plugins':{
              'section':'main',
              'description':"what plugins do we load, comma separated",
              'default':"",
            },

            'bindaddress':{
              'section':'main',
              'description':"address postomaat should listen on. usually 127.0.0.1 so connections are accepted from local host only",
              'default':"127.0.0.1",
            },
                                        
            'incomingport':{
              'section':'main',
              'description':"incoming port",
              'default':"9998",
            },
        
            #performance section
            'minthreads':{
                'default':"2",
                'section':'performance',
                'description':'minimum scanner threads',
            },
            'maxthreads':{
                'default':"40",
                'section':'performance',
                'description':'maximum scanner threads',
            },
                           
            #  plugin alias
             'call-ahead':{
                'default':"postomaat.plugins.call-ahead.AddressCheck",
                'section':'PluginAlias',
            },
                           
             'dbwriter':{
                'default':"postomaat.plugins.dbwriter.DBWriter",
                'section':'PluginAlias',
            },       
        }
        self.config=config
        self.servers=[]
        self.logger=self._logger()
        self.stayalive=True
        self.threadpool=None
        self.debugconsole = False
        
        
    def _logger(self):
        myclass=self.__class__.__name__
        loggername="%s.%s"%(BASENAME,myclass)
        return logging.getLogger(loggername)
    
    def startup(self):
        ok=self.load_plugins()
        if not ok:
            sys.stderr.write("Some plugins failed to load, please check the logs. Aborting.\n")
            self.logger.info('postomaat shut down after fatal error condition')
            sys.exit(1)

        self.logger.info("Init Threadpool")
        try:
            minthreads=self.config.getint('performance','minthreads')
            maxthreads=self.config.getint('performance','maxthreads')
        except ConfigParser.NoSectionError:
            self.logger.warning('Performance section not configured, using default thread numbers')
            minthreads=1
            maxthreads=3
        
        queuesize=maxthreads*10
        self.threadpool=ThreadPool(minthreads, maxthreads, queuesize)
        
        self.logger.info("Init policyd Engine")
        
        ports=self.config.get('main', 'incomingport')
        for portconfig in ports.split():
            #plugins
            plugins=self.plugins
            if ':' in portconfig:
                port,pluginlist=portconfig.split(':')
                port=int(port.strip())
                plugins,ok=self._load_all(pluginlist)
                if not ok:
                    self.logger.error("Could not startup engine on port %s, some plugins failed to load"%port)
                    continue
            else:
                port=int(portconfig.strip())
            
            server=PolicyServer(self,port=port,address=self.config.get('main', 'bindaddress'),plugins=plugins)
            
            thread.start_new_thread(server.serve, ())
            self.servers.append(server)
        self.logger.info('Startup complete')
        if self.debugconsole:
            self.run_debugconsole()
        else:
            while self.stayalive:
                try:
                    time.sleep(10)
                except KeyboardInterrupt:
                    self.shutdown()

    def run_debugconsole(self):
        # do not import readline at the top, it will cause undesired output, for example when generating the default config
        # http://stackoverflow.com/questions/15760712/python-readline-module-prints-escape-character-during-import
        import readline

        print "Interactive Console started"
        print ""
        print "pre-defined locals:"

        mc = self
        print "mc : maincontroller"

        terp = code.InteractiveConsole(locals())
        terp.interact("")

    def reload(self):
        """apply config changes"""
        self.logger.info('Applying configuration changes...')
        
        #threadpool changes?
        minthreads=self.config.getint('performance','minthreads')
        maxthreads=self.config.getint('performance','maxthreads')
        
        if self.threadpool.minthreads!=minthreads or self.threadpool.maxthreads!=maxthreads:
            self.logger.info('Threadpool config changed, initialising new threadpool')
            queuesize=maxthreads*10
            currentthreadpool=self.threadpool
            self.threadpool=ThreadPool(minthreads, maxthreads, queuesize)
            currentthreadpool.stayalive=False
            
        #smtp engine changes?
        ports=self.config.get('main', 'incomingport')
        portlist=map(int,ports.split(','))
        
        for port in portlist:
            alreadyRunning=False
            for serv in self.servers:
                if serv.port==port:
                    alreadyRunning=True
                    break
            
            if not alreadyRunning:
                server=PolicyServer(self,port=port,address=self.config.get('main', 'bindaddress'))
                thread.start_new_thread(server.serve, ())
                self.smtpservers.append(server)
        
        servercopy=self.servers[:] 
        for serv in servercopy:
            if serv.port not in portlist:
                self.logger.info('Closing server socket on port %s'%serv.port)
                serv.shutdown()
                self.servers.remove(serv)
        
        self.logger.info('Config changes applied')
    
    
    def test(self,valuedict,port=None):
        """dryrun without postfix"""
        suspect=Suspect(valuedict)
        if not self.load_plugins():
            sys.exit(1)

        if port!=None:
            plugins=None
            ports=self.config.get('main', 'incomingport')
            for portconfig in ports.split():
                if ':' in portconfig:
                    pport,pluginlist=portconfig.split(':')
                    if pport!=port:
                        continue
                    plugins,ok=self._load_all(pluginlist)
                    break
                else:
                    if portconfig==port: #port with default config
                        plugins=self.plugins
                        break
        else:
            plugins=self.plugins

        if plugins==None:
            raise Exception("no plugin configuration for current port selection")
        sesshandler=SessionHandler(None, self.config, plugins)
        sesshandler.run_plugins(suspect, plugins)
        action=sesshandler.action
        arg=sesshandler.arg
        return (action,arg)
         
    def shutdown(self):
        for server in self.servers:
            self.logger.info('Closing server socket on port %s'%server.port)
            server.shutdown()
        
        self.threadpool.stayalive=False
        self.stayalive=False
        self.logger.info('Shutdown complete')
        self.logger.info('Remaining threads: %s' %threading.enumerate())
        
   
   
    def lint(self):
        errors=0
        from postomaat.funkyconsole import FunkyConsole
        fc=FunkyConsole()
        print fc.strcolor('Loading plugins...','magenta')
        if not self.load_plugins():
            print fc.strcolor('At least one plugin failed to load','red')
        print fc.strcolor('Plugin loading complete','magenta')
        
        print "Linting ",fc.strcolor("main configuration",'cyan')
        if not self.checkConfig():
            print fc.strcolor("ERROR","red")
        else:
            print fc.strcolor("OK","green")
    
        
        
        allplugins=self.plugins
        
        for plugin in allplugins:
            print
            print "Linting Plugin ",fc.strcolor(str(plugin),'cyan'),'Config section:',fc.strcolor(str(plugin.section),'cyan')
            try:
                result=plugin.lint()
            except Exception,e:
                print "ERROR: %s"%e
                result=False
            
            if result:
                print fc.strcolor("OK","green")
            else:
                errors=errors+1
                print fc.strcolor("ERROR","red")
        print "%s plugins reported errors."%errors
        
        
    
    def checkConfig(self):
        """Check if all requred options are in the config file
        Fill missing values with defaults if possible
        """
        allOK=True
        for config,infodic in self.requiredvars.iteritems():
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


    def get_component_by_alias(self,pluginalias):
        """Returns the full plugin component from an alias. if this alias is not configured, return the original string"""
        if not self.config.has_section('PluginAlias'):
            return pluginalias
        
        if not self.config.has_option('PluginAlias', pluginalias):
            return pluginalias
        
        return self.config.get('PluginAlias', pluginalias)
    
    def load_plugins(self):
        """load plugins defined in config"""
        
        allOK=True

        plugdir=self.config.get('main', 'plugindir').strip()
        if plugdir!="" and not os.path.isdir(plugdir):
            self._logger().warning('Plugin directory %s not found'%plugdir)
        
        if plugdir!="":   
            self._logger().debug('Searching for additional plugins in %s'%plugdir)
            if plugdir not in sys.path:
                sys.path.insert(0,plugdir)
    
        #self._logger().info('Module search path %s'%sys.path)
        self._logger().debug('Loading scanner plugins')
        
        newplugins,loadok=self._load_all(self.config.get('main', 'plugins'))
        if not loadok:
            allOK=False
        
        if allOK:
            self.plugins=newplugins
            self.propagate_plugin_defaults()
            
        return allOK
    
    def _load_all(self,configstring):
        """load all plugins from config string. returns tuple ([list of loaded instances],allOk)"""
        pluglist=[]
        config_re=re.compile("""^(?P<structured_name>[a-zA-Z0-9\.\_\-]+)(?:\((?P<config_override>[a-zA-Z0-9\.\_]+)\))?$""")
        allOK=True
        plugins=configstring.split(',')
        for plug in plugins:
            if plug=="":
                continue
            m=config_re.match(plug)
            if m==None:
                self.logger.error('Invalid Plugin Syntax: %s'%plug)
                allOK=False
                continue
            structured_name,configoverride=m.groups()
            structured_name=self.get_component_by_alias(structured_name)
            try:
                plugininstance=self._load_component(structured_name,configsection=configoverride)
                pluglist.append(plugininstance)
            except Exception,e:
                self._logger().error('Could not load plugin %s : %s'%(structured_name,e))
                exc=traceback.format_exc()
                self._logger().error(exc)
                allOK=False
        
        return pluglist,allOK
    
    
    def _load_component(self,structured_name,configsection=None):
        #from: http://mail.python.org/pipermail/python-list/2003-May/204392.html
        component_names = structured_name.split('.')
        mod = __import__('.'.join(component_names[:-1]))
        for component_name in component_names[1:]:
            mod = getattr(mod, component_name)
        
        if configsection==None:
            plugininstance=mod(self.config)
        else:
            #check if plugin supports config override
            if 'section' in inspect.getargspec(mod.__init__)[0]:
                plugininstance=mod(self.config,section=configsection)
            else:
                raise Exception,'Cannot set Config Section %s : Plugin %s does not support config override'%(configsection,mod)
        return plugininstance
    
    def propagate_defaults(self,requiredvars,config,defaultsection=None):
        """propagate defaults from requiredvars if they are missing in config"""
        for option,infodic in requiredvars.iteritems():
            if 'section' in infodic:
                section=infodic['section']
            else:
                section=defaultsection
                
            default=infodic['default']
            
            if not config.has_section(section):
                config.add_section(section)
                
            if not config.has_option(section,option):
                config.set(section,option,default)
    
    def propagate_core_defaults(self):
        """check for missing core config options and try to fill them with defaults
        must be called before we can do plugin loading stuff
        """
        self.propagate_defaults(self.requiredvars, self.config,'main')
    
    def propagate_plugin_defaults(self):
        """propagate defaults from loaded lugins"""
        for plug in self.plugins:
            if hasattr(plug,'requiredvars'):
                requiredvars=getattr(plug,'requiredvars')
                if type(requiredvars)==dict:
                        self.propagate_defaults(requiredvars, self.config, plug.section)
            
class PolicyServer(object):    
    def __init__(self, controller,port=10025,address="127.0.0.1",plugins=None):
        self.logger=logging.getLogger("%s.proto.incoming.%s"%(BASENAME,port))
        self.logger.debug('Starting incoming policy server on Port %s'%port)
        self.port=port
        self.controller=controller
        self.stayalive=1
        if plugins==None:
            self.plugins=controller.plugins
        else:
            self.plugins=plugins
            
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((address, port))
            self._socket.listen(5)
        except Exception,e:
            self.logger.error('Could not start incoming policy server: %s'%e)
            sys.exit(1)
   
   
    def shutdown(self):
        self.stayalive=False
        self._socket.close()
        
    def serve(self):
        #disable to debug... 
        use_multithreading=True
        controller=self.controller
        
        self.logger.info('policy server running on port %s'%self.port)
        if use_multithreading:
                threadpool=self.controller.threadpool
        while self.stayalive:
            try:
                self.logger.debug('Waiting for connection...')
                nsd = self._socket.accept()
                if not self.stayalive:
                    break
                engine = SessionHandler(nsd[0],controller.config,self.plugins)
                self.logger.debug('Incoming connection from %s'%str(nsd[1]))
                if use_multithreading:
                    #this will block if queue is full
                    threadpool.add_task(engine)
                else:
                    engine.handlesession()
            except Exception,e:
                self.logger.error('Exception in serve(): %s'%str(e))

                 
class PolicydSession(object):
    def __init__(self, socket,config):
        self.config=config
       
        self.socket = socket;
        self.logger=logging.getLogger("%s.policysession"%BASENAME)
        self.file=self.socket.makefile('r')
        self.values={}
        
    def endsession(self,action,arg):
        ret=action
        if arg!=None and arg.strip()!="":
            ret="%s %s"%(action,arg.strip())
        self.socket.send('action=%s\n\n'%ret)
        self.closeconn()
        
      
    def closeconn(self):
        self.socket.close()
        
    def getrequest(self):
        """return true if mail got in, false on error Session will be kept open"""
        while 1:
            line=self.file.readline()
            line=line.strip()
            if line=='':
                return True
            try:
                (key,val)=line.split('=',1)
                self.values[key]=val
            except Exception,e:
                self.logger.error('Invalid Protocol line: %s'%line)
                return False
            
        return False


     


