# -*- coding: UTF-8 -*-

from postomaat.shared import DUNNO, Suspect
import logging
import sys
import traceback
import time
import socket


class SessionHandler(object):

    """thread handling one message"""

    def __init__(self, incomingsocket, config, plugins):
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
        try:
            self.set_threadinfo('receiving message')
            sess = PolicydSession(self.incomingsocket, self. config)
            success = sess. getrequest()
            if not success:
                self.logger.error('incoming request did not finish')
                sess.closeconn()

            values = sess. values
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
        # IMPORTANT: Shutdown the socket explicitly
        #            before closing, otherwise the next
        #            incoming connection in PolicyServer
        #            might time-out in the socket.accept()
        #            statement
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
