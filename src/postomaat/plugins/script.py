# -*- coding: UTF-8 -*-
#   Copyright 2012-2018 Oli Schacher
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
#

from postomaat.shared import ScannerPlugin,DUNNO,ACCEPT,DEFER,REJECT
import os
import traceback
import time
try:
    # python >= 2.5
    import runpy
    # needed since "execfile" is not
    # available in python >= 3
except ImportError:
    pass

class Stopped(Exception):
    pass

class ScriptFilter(ScannerPlugin):
    """ This plugins executes scripts found in a specified directory.
This can be used to quickly add a custom filter script without changing the postomaat configuration.

Filterscripts must be written in standard python but with the file ending ``.pmf`` ("postomaat filter")

scripts are reloaded for every message executed in alphabetic order

The API is basically the same as for normal plugins within the ``examine()`` method, with a few special cases:

there is no 'self' which means:

    * access the configuration by using ``config`` directly (instead of ``self.config``)
    * use ``debug('hello world')`` instead of ``self.logger.debug('hello world')``

the script should not return anything, but change the available variables ``action`` and ``message`` instead
(``DUNNO``, ``REJECT``, ``DEFER``, ``ACCEPT`` are already imported)

use ``stop()`` to exit the script
    
    
example script: 
(put this in /etc/postomaat/scriptfilter/99_demo.pmf for example)

::

    #block all messages from evilsender.example.com
    #TODO: demo script here
    action=REJECT
    message="you shall not pass"


    """
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.requiredvars={
            'scriptdir':{
                'default':'/etc/postomaat/scriptfilter',
                'description':'Dir that contains the scripts (*.pmf files)',
            }                  
        }

    def examine(self,suspect):
        starttime=time.time()
        scripts=self.get_scripts()
        retaction=DUNNO
        retmessage=''
        for script in scripts:
            self.logger.debug("Executing script %s"%script)
            sstart=time.time()
            action,message=self.exec_script(suspect, script)
            send=time.time()
            self.logger.debug("Script %s done in %.4fs result: %s %s"%(script,send-sstart,action,message))
            if action!=DUNNO:
                retaction=action
                retmessage=message
                break
            
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['ScriptFilter.time']="%.4f"%difftime
        return retaction,retmessage
    
    
    def lint(self):
        allok=(self.checkConfig() and self.lint_code())
        return allok
    
    def lint_code(self):
        scriptdir=self.config.get(self.section,'scriptdir')
        if not os.path.isdir(scriptdir):
            print("Script dir %s does not exist"%scriptdir)
            return False
        scripts=self.get_scripts()
        counter=0
        for script in scripts:
            counter+=1
            try:
                with open(script,'r') as fp:
                    source = fp.read()
                compile(source,script,'exec')
            except Exception:
                trb=traceback.format_exc()
                print("Script %s failed to compile: %s"%(script,trb))
                return False
        print("%s scripts found"%counter)
        return True
    
    def _debug(self,suspect,message):
        self.logger.debug(message)
        
        
    
    def exec_script(self,suspect,filename):
        action=DUNNO
        message=''
        debug = lambda message: self._debug(suspect,message)
        
        def stop():
            raise Stopped()
        
        scriptenv=dict(
                    action=action,
                    message=message,
                    suspect=suspect,
                    debug=debug,
                    config=self.config,
                    stop=stop,
                    DUNNO=DUNNO,ACCEPT=ACCEPT,DEFER=DEFER,REJECT=REJECT,
                    
        )
        
        try:
            try:
                # does not exist for python >= 3
                execfile(filename, scriptenv)
            except NameError:
                # runpy exists since python 2.5
                scriptenv = runpy.run_path(filename, scriptenv)
            except Exception as e:
                raise e


            action=scriptenv['action']
            message=scriptenv['message']
        except Stopped:
            pass
        except Exception:
            trb=traceback.format_exc()
            self.logger.error("Script %s failed: %s"%(filename,trb))
            
        return action,message
    
    def get_scripts(self):
        scriptdir=self.config.get(self.section,'scriptdir')
        if os.path.isdir(scriptdir):
            filelist=os.listdir(scriptdir)
            scripts=[os.path.join(scriptdir,f) for f in filelist if f.endswith('.pmf')]
            scripts=sorted(scripts)
            return scripts
        else:
            return []
    
    def __str__(self):
        return "Scriptfilter Plugin"