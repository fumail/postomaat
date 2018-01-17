# -*- coding: utf-8 -*-
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

import logging
import sys
import os
import thread
import socket
import time
import traceback
import ConfigParser
import re
import inspect
from postomaat.shared import Suspect
from postomaat.scansession import SessionHandler
import threading
from threadpool import ThreadPool
import postomaat.procpool
import multiprocessing
import code
from multiprocessing.reduction import ForkingPickler
import StringIO



HOSTNAME=socket.gethostname()
         
   

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
            'backend': {
                'default': "thread",
                'section': 'performance',
                'description': "Method for parallelism, either 'thread' or 'process' ",
            },
            'initialprocs': {
                'default': "0",
                'section': 'performance',
                'description': "Initial number of processes when backend='process'. If 0 (the default), automatically selects twice the number of available virtual cores. Despite its 'initial'-name, this number currently is not adapted automatically.",
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
        self.procpool=None
        self.debugconsole = False
        
        
    def _logger(self):
        myclass=self.__class__.__name__
        loggername="%s.%s"%(__package__, myclass)
        return logging.getLogger(loggername)

    def _start_threadpool(self):
        self.logger.info("Init Threadpool")
        try:
            minthreads = self.config.getint('performance', 'minthreads')
            maxthreads = self.config.getint('performance', 'maxthreads')
        except configparser.NoSectionError:
            self.logger.warning(
                'Performance section not configured, using default thread numbers')
            minthreads = 1
            maxthreads = 3

        queuesize = maxthreads * 10
        return ThreadPool(minthreads, maxthreads, queuesize)

    def _start_processpool(self):
        numprocs = self.config.getint('performance','initialprocs')
        if numprocs < 1:
            numprocs = multiprocessing.cpu_count() *2
        self.logger.info("Init process pool with %s worker processes"%(numprocs))
        pool = postomaat.procpool.ProcManager(numprocs = numprocs, config = self.config)
        return pool

    def startup(self):
        ok=self.load_plugins()
        if not ok:
            sys.stderr.write("Some plugins failed to load, please check the logs. Aborting.\n")
            self.logger.info('postomaat shut down after fatal error condition')
            sys.exit(1)

        backend = self.config.get('performance','backend')
        if backend == 'process':
            self.procpool = self._start_processpool()
        else: # default backend is 'thread'
            self.threadpool = self._start_threadpool()

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
        if self.config.get('performance','backend') == 'thread' and self.threadpool is not None:
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
                self.servers.append(server)
        
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

        if port is not None:
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

        if plugins is None:
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
        
        if self.threadpool:
            self.threadpool.stayalive = False
        if self.procpool:
            self.procpool.stayalive = False
        self.stayalive=False
        self.logger.info('Shutdown complete')
        self.logger.info('Remaining threads: %s' %threading.enumerate())
        
    def _lint_dependencies(self, fc):
        print(fc.strcolor('Checking dependencies...', 'magenta'))
        try:
            import sqlalchemy
            print(fc.strcolor('sqlalchemy: Version %s installed' % sqlalchemy.__version__, 'green'))
        except ImportError:
            print(fc.strcolor('sqlalchemy: not installed', 'yellow') +
                  " Optional dependency, required if you want to enable any database lookups")
        
    def lint(self):
        errors=0
        from postomaat.funkyconsole import FunkyConsole
        fc=FunkyConsole()
        self._lint_dependencies(fc)
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
            except Exception as e:
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
            self.logger.warning('Plugin directory %s not found'%plugdir)
        
        if plugdir!="":   
            self.logger.debug('Searching for additional plugins in %s'%plugdir)
            if plugdir not in sys.path:
                sys.path.insert(0,plugdir)
    
        self.logger.debug('Module search path %s'%sys.path)
        self.logger.debug('Loading scanner plugins')
        
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
            if m is None:
                self.logger.error('Invalid Plugin Syntax: %s'%plug)
                allOK=False
                continue
            structured_name,configoverride=m.groups()
            structured_name=self.get_component_by_alias(structured_name)
            try:
                plugininstance=self._load_component(structured_name,configsection=configoverride)
                pluglist.append(plugininstance)
            except Exception as e:
                self.logger.error('Could not load plugin %s : %s'%(structured_name, str(e)))
                exc=traceback.format_exc()
                self.logger.error(exc)
                allOK=False
        
        return pluglist,allOK
    
    
    def _load_component(self,structured_name,configsection=None):
        #from: http://mail.python.org/pipermail/python-list/2003-May/204392.html
        component_names = structured_name.split('.')
        mod = __import__('.'.join(component_names[:-1]))
        for component_name in component_names[1:]:
            mod = getattr(mod, component_name)
        
        if configsection is None:
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
        self.logger=logging.getLogger("%s.proto.incoming.%s"%(__package__, port))
        self.logger.debug('Starting incoming policy server on Port %s'%port)
        self.port=port
        self.controller=controller
        self.stayalive=1
        if plugins is None:
            self.plugins=controller.plugins
        else:
            self.plugins=plugins
            
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((address, port))
            self._socket.listen(5)
        except Exception as e:
            self.logger.error('Could not start incoming policy server: %s'%e)
            sys.exit(1)
   
   
    def shutdown(self):
        self.stayalive=False
        self._socket.close()
        
    def serve(self):

        controller = self.controller
        threadpool = self.controller.threadpool
        procpool   = self.controller.procpool

        self.logger.info('policy server running on port %s'%self.port)
        while self.stayalive:
            try:
                self.logger.debug('Waiting for connection...')
                sock, addr = self._socket.accept()
                if not self.stayalive:
                    break
                engine = SessionHandler(sock,controller.config,self.plugins)
                self.logger.debug('Incoming connection from %s'%str(addr))
                if threadpool:
                    #this will block if queue is full
                    self.controller.threadpool.add_task(engine)
                elif procpool:
                    # in multi processing, the other process manages configs and plugins itself, we only pass the minimum required information:
                    # a pickled version of the socket (this is no longer required in python 3.4, but in python 2 the multiprocessing queue can not handle sockets
                    # see https://stackoverflow.com/questions/36370724/python-passing-a-tcp-socket-object-to-a-multiprocessing-queue
                    #handler_classname = self.protohandlerclass.__name__
                    #handler_modulename = self.protohandlerclass.__module__
                    #task = forking_dumps(sock),handler_modulename, handler_classname
                    task = forking_dumps(sock)
                    procpool.add_task(task)
                else:
                    engine.handlesession()
            except Exception as e:
                self.logger.error('Exception in serve(): %s'%str(e))

def forking_dumps(obj):
    """ Pickle a socket This is required to pass the socket in multiprocessing"""
    buf = StringIO.StringIO()
    ForkingPickler(buf).dump(obj)
    return buf.getvalue()


