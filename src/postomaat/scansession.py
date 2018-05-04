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

from postomaat.shared import DUNNO, DEFER, REJECT, Suspect
from postomaat.MailAddrLegitimateChecker import Default, LazyQuotedLocalPart
import logging
import sys
import traceback
import time
import socket


class SessionHandler(object):

    """thread handling one message"""

    def __init__(self, incomingsocket, config, prependers, plugins, appenders):
        del prependers, appenders # fuglu api compatibility
        self.incomingsocket = incomingsocket
        self.logger = logging.getLogger("%s.SessionHandler" % __package__)
        self.action = DUNNO
        self.arg = ""
        self.config = config
        self.plugins = plugins
        self.workerthread = None
    
    
    def set_threadinfo(self, status):
        if self.workerthread is not None:
            self.workerthread.threadinfo = status
    
    
    def handlesession(self, workerthread=None):
        self.workerthread = workerthread
        sess = None
        
        #--
        # setup compliance checker if not already set up
        #--
        #
        # Mail Address compliance check is global, make sure it is updated when config is changed
        try:
            addComCheck = self.config.get('main','address_compliance_checker')
        except Exception as e:
            # might happen for some tests which do not propagate defaults
            addComCheck = Default

        if addComCheck == "Default" and not isinstance(Suspect.addrIsLegitimate,Default):
            Suspect.addrIsLegitimate = Default()
        elif addComCheck == "LazyQuotedLocalPart" and not isinstance(Suspect.addrIsLegitimate,LazyQuotedLocalPart):
            Suspect.addrIsLegitimate = LazyQuotedLocalPart()
        else:
            self.logger.error('Address Compliance Checker not recognized -> use Default')
            Suspect.addrIsLegitimate = Default()
        
        try:
            self.set_threadinfo('receiving message')
            sess = PolicydSession(self.incomingsocket, self. config)
            success = sess. getrequest()
            if not success:
                self.logger.error('incoming request did not finish')
                sess.closeconn()

            values = sess.values
            suspect = Suspect(values)

            # store incoming port to tag, could be used to disable plugins
            # based on port
            try:
                port = sess.socket . getsockname()[1]
                if port is not None:
                    suspect.tags['incomingport'] = port
            except Exception as e:
                self.logger.warning('Could not get incoming port: %s' % str(e))

            self.set_threadinfo("Handling message %s" % suspect)
            starttime = time.time()
            self.run_plugins(suspect, self.plugins)

            # how long did it all take?
            difftime = time.time() - starttime
            suspect.tags['postomaat.scantime'] = "%.4f" % difftime

            # checks done.. print out suspect status
            self.logger.debug(suspect)
            self.set_threadinfo("Finishing message %s" % suspect)
            sess.endsession(self.action, self.arg)

        except KeyboardInterrupt:
            sys.exit(0)
            
        except ValueError:
            if sess is not None:
                # Error in envelope send/receive address
                try:
                    address_compliance_fail_action = self.config.get('main','address_compliance_fail_action').lower()
                except Exception as e:
                    address_compliance_fail_action = "defer"
    
                try:
                    message = self.config.get('main','address_compliance_fail_message')
                except Exception as e:
                    message = "invalid sender or recipient address"
                
                if address_compliance_fail_action == "reject":
                    sess.endsession(REJECT, message)
                else:
                    sess.endsession(DEFER, message)
                sess.closeconn()
                
        except Exception as e:
            self.logger.exception(e)
            if sess is not None:
                sess.closeconn()
        self.logger.debug('Session finished')
    
    
    def run_plugins(self, suspect, pluglist):
        """Run scannerplugins on suspect"""
        for plugin in pluglist:
            try:
                self.logger.debug('Running plugin %s' % plugin)
                self.set_threadinfo(
                    "%s : Running Plugin %s" % (suspect, plugin))
                ans = plugin.examine(suspect)
                arg = None
                if isinstance(ans, tuple):
                    result, arg = ans
                else:
                    result = ans

                if result is None:
                    result = DUNNO
                else:
                    result = result.strip().lower()
                self.action = result
                self.arg = arg
                suspect.tags['decisions'].append((str(plugin), result))
                self.logger.debug('Plugin sez: %s (arg=%s)' % (result, arg))

                if result != DUNNO:
                    self.logger.debug(
                        'Plugin makes a decision other than DUNNO - not running any other plugins')
                    break

            except Exception:
                exc = traceback. format_exc()
                self.logger.error('Plugin %s failed: %s' % (str(plugin), exc))


class PolicydSession(object):

    def __init__(self, socket, config):
        self.config = config

        self.socket = socket
        self.logger = logging.getLogger("%s.policysession" % __package__)
        self.file = self.socket.makefile('r')
        self.values = {}

    def endsession(self, action, arg):
        ret = action
        if arg is not None and arg.strip() != "":
            ret = "%s %s" % (action, arg.strip())
        self.socket.send(('action=%s\n\n' % ret).encode())
        self.closeconn()

    def closeconn(self):
        if sys.version_info > (3,):
            # IMPORTANT: Python 3
            #            Shutdown the socket explicitly
            #            before closing, otherwise the next
            #            incoming connection in PolicyServer
            #            might time-out in the socket.accept()
            #            statement
            #            -> seems to create problems for python 2.7.9
            #               whereas it works with 2.7.5 where both versions
            #               seem to work
            #            -> decision: use only for python > 3
            self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def getrequest(self):
        """return true if mail got in, false on error Session will be kept open"""
        while True:
            line = self.file.readline()
            line = line.strip()
            if line == '':
                return True
            try:
                key, val = line.split('=', 1)
                self.values[key] = val
            except Exception:
                self.logger.error('Invalid Protocol line: %s' % line)
                break

        return False
