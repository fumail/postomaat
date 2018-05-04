# -*- coding: UTF-8 -*-
import time
from threading import Lock
from postomaat.shared import ScannerPlugin, DUNNO, string_to_actioncode, apply_template
from postomaat.extensions.sql import SQL_EXTENSION_ENABLED, get_session
import re
import os
import sys
from hashlib import md5
REDIS_AVAILABLE =  0
try:
    import redis
    REDIS_AVAILABLE = 1
except ImportError:
    pass

if sys.version_info > (3,):
    unicode = str


AVAILABLE_RATELIMIT_BACKENDS={}

class RollingWindowBackend(object):
    def __init__(self,backendconfig):
        self._real_init(backendconfig)

    def check_count(self,eventname,timediff):
        """record a event. Returns the current count"""
        now=self.add(eventname)
        then=now-timediff
        self.clear(eventname,then)
        count = self.count(eventname)
        return count

    def check_allowed(self,eventname,timediff,limit):
        count = self.check_count(eventname,timediff)
        return count<=limit

    def add(self,eventname):
        """add a tick to the event and return its timestamp"""
        now=time.time()
        self._real_add(eventname,now)
        return now

    def clear(self,eventname,abstime=None):
        """clear events before abstime in secs. if abstime is not provided, clears the whole queue"""
        if abstime is None:
            abstime=int(time.time())
        self._real_clear(eventname,abstime)

    def count(self,eventname):
        """return the current number of events in the queue"""
        return self._real_count(eventname)

    ## -- override these in other backends

    def _real_init(self,config):
        self.memdict={}
        self.lock = Lock()

    def _real_add(self,eventname,timestamp): #override this!
        self.lock.acquire()
        if eventname in self.memdict:
            self.memdict[eventname].append(timestamp)
        else:
            self.memdict[eventname]=[timestamp,]
        self.lock.release()

    def _real_clear(self,eventname,abstime):
        if eventname not in self.memdict:
            return
        self.lock.acquire()
        try:
            while self.memdict[eventname][0]<abstime:
                del self.memdict[eventname][0]
        except IndexError: #empty list, remove
            del self.memdict[eventname]

        self.lock.release()

    def _real_count(self,eventname):
        self.lock.acquire()
        try:
            count = len(self.memdict[eventname])
        except KeyError:
            count = 0
        self.lock.release()
        return count

AVAILABLE_RATELIMIT_BACKENDS['memory']=RollingWindowBackend

if REDIS_AVAILABLE:
    class RedisBackend(RollingWindowBackend): # TODO
        def _fix_eventname(self,eventname):
            if len(eventname)>255:
                eventname = md5(eventname).hexdigest()
            return eventname

        def _real_init(self,backendconfig):
            parts = backendconfig.split(':')
            host = parts[0]
            if len(parts)>1:
                port = int(parts[1])
            else:
                port = 6379
            if len(parts)>2:
                db = int(parts[2])
            else:
                db = 0
            self.redis = redis.StrictRedis(host=host,port=port,db=db)

        def _real_add(self,eventname,timestamp):
            self.redis.zadd(self._fix_eventname(eventname), timestamp, timestamp)

        def _real_clear(self,eventname,abstime):
            self.redis.zremrangebyscore(self._fix_eventname(eventname), '-inf', abstime)

        def _real_count(self,eventname):
            return self.redis.zcard(self._fix_eventname(eventname))

    AVAILABLE_RATELIMIT_BACKENDS['redis']=RedisBackend

if SQL_EXTENSION_ENABLED:
    from sqlalchemy import Column, Integer,  Unicode,BigInteger, Index
    from sqlalchemy.sql import and_
    from sqlalchemy.ext.declarative import declarative_base
    DeclarativeBase = declarative_base()
    metadata = DeclarativeBase.metadata
    
    class Event(DeclarativeBase):
        __tablename__ = 'postomaat_ratelimit'
        eventid = Column(BigInteger, primary_key=True)
        eventname = Column(Unicode(255), nullable=False)
        occurence = Column(Integer, nullable=False)
        __table_args__ = (Index('udx_ev_oc', 'eventname', 'occurence'),)

    class SQLAlchemyBackend(RollingWindowBackend):
        def _fix_eventname(self,eventname):
            if type(eventname)!=unicode:
                eventname=unicode(eventname)
            if len(eventname)>255:
                eventname = unicode(md5(eventname).hexdigest())
            return eventname

        def _real_init(self,backendconfig):
            self.session = get_session(backendconfig)
            metadata.create_all(bind=self.session.bind)

        def _real_add(self,eventname,timestamp):
            ev = Event()
            ev.eventname = self._fix_eventname(eventname)
            ev.occurence = int(timestamp)
            self.session.add(ev)
            self.session.flush()

        def _real_clear(self,eventname,abstime):
            eventname = self._fix_eventname(eventname)
            self.session.query(Event).filter(and_(Event.eventname==eventname, Event.occurence < abstime)).delete()
            self.session.flush()

        def _real_count(self,eventname):
            eventname = self._fix_eventname(eventname)
            result = self.session.query(Event).filter(Event.eventname == eventname).count()
            return result

    AVAILABLE_RATELIMIT_BACKENDS['sqlalchemy']=SQLAlchemyBackend

class Limiter(object):
    def __init__(self):
        self.name = None
        self.max = -1 # negative value: no limit
        self.timespan = 1
        self.fields=[]
        self.regex = None
        self.skip = None
        self.action = DUNNO
        self.message = 'Limit exceeded'

    def __str__(self):
        return "<Limiter name=%s rate=%s/%s fields=%s>"%(self.name,self.max,self.timespan,",".join(self.fields))


class RateLimitPlugin(ScannerPlugin):
    """This is a generic rolling window rate limiting plugin. It allows limiting the amount of accepted messages based on any combination of supported SuspectFilter fields.
    This means you could for example limit the number of similar subjects by sender domain to implement a simple bulk filter.

    Important notes:
        - This plugin is experimental and has not been tested in production
        - This plugin only makes sense in pre-queue mode.
        - The content filter stage is usually *not* the best place to implement rate-limiting.
          Faster options are postfix built-in rate limits or a policy access daemon
          which doesn't need to accept the full message to make a decision
        - the backends don't automatically perform global expiration of all events.
          Old entries are only cleared per event the next time the same event happens.
          Add a cron job for your backend to clear all old events from time to time.

    Supported backends:
        - memory: stores events in memory. Do not use this in production.
        - sqlalchemy: Stores events in a SQL database. Recommended for small/low-traffic setups
        - redis: stores events in a redis database. This is the fastest and therefore recommended backend.

    Configuration example for redis. Prerequisite: python redis module
        backendtype = redis
        backendconfig = localhost:6379:0

    Configuration example for mysql: Prerequisite: python sqlalchemy module. The database must exist. The table will be created automatically.
        backendtype = sqlalchemy
        backendconfig = mysql://root@localhost/postomaat

    ratelimit.conf format: (not final yet)

    Each limiter is defined by a line which must match the following format. Each limiter is evaluated in the order specified.

    limit name=**name** rate=**max**/**timeframe** fields=**fieldlist** [match=/**filter regex**/ [skip=**skiplist** ]] action=**action** message=**message**

        **name**        : a descriptive name for this filter, one word. Required to reference in skip lists
        **max**         : the maximum number of events that may occur in the specified timeframe before an action is limited.
                          Specify a negative value to indicate "no limit"
        **timeframe**   : Timeframe for the limit
        **fields**      : comma separated list of fields which should be used as unique values to limit
        **match** (optional): regular expression to apply to the actuall values. The limiter is only applied if this regular expression matches.
                              If the limiter consists of multiple input fields,
                              The regex will be applied to the comma separated list of field values.
        **skip** (optional):  Comma separated list of subsequent limiter names, that should be skipped if this this limiter's regex matched the input values.
                              Used for overrides.
        **action**      : Action that should be performed if the limit is exceeded. ( REJECT / DEFER / ... )
        **message**     : Message returned to the connecting client


    Examples:

    # no sending limit for our newsletter
    limit name=newsletter rate=-1/1 fields=from_address match=/^newsletter@example\.com$/ skip=fromaddr,serverhelo action=DUNNO message=OK

    # max 10 messages in 30 seconds per unique sender address:
    limit name=fromaddr rate=10/30 fields=from_address action=REJECT message=Too many messages from ${from_address}

    # max 100 messages with same subject per hour per server helo
    limit name=serverhelo rate=100/3600 fields=clienthelo,subject action=REJECT message=Bulk message detected

    """
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {

            'limiterfile': {
                'default': '/etc/postomaat/ratelimit.conf',
                'description': 'file based rate limits',
            },

            'backendtype':{
                'default': 'memory',
                'description': 'type of backend where the events are stored. memory is only recommended for low traffic standalone systems. alternatives are: redis, sqlalchemy'
            },

            'backendconfig':{
                'default': '',
                'description': 'backend specific configuration. sqlalchemy: the database url, redis: hostname:port:db'
            }

        }

        self.logger = self._logger()
        self.backend_instance = None
        self.limiters = None

    #TODO: make action and message optional
    def load_limiter_config(self,text):
        patt = re.compile(r'^limit\s+name=(?P<name>[^\s]+)\s+rate=(?P<max>\-?\d{1,10})\/(?P<time>\d{1,10})\s+fields=(?P<fieldlist>[^\s]+)(\s+match=\/(?P<matchregex>.+)\/(\s+skip=(?P<skiplist>[^\s]+))?)?\s+action=(?P<action>[^\s]+)\s+message=(?P<message>.*)$')
        limiters = []
        lineno=0
        for line in text.split('\n'):
            lineno+=1
            line=line.strip()
            if line.startswith('#') or line.strip()=='':
                continue
            match= patt.match(line)
            if match is None:
                self.logger.error('cannot parse limiter config line %s'%lineno)
                continue
            gdict = match.groupdict()
            limiter = Limiter()
            limiter.name = gdict['name']
            limiter.max = int(gdict['max'])
            limiter.timespan = int(gdict['time'])
            limiter.fields = gdict['fieldlist'].split(',')
            limiter.regex = gdict['matchregex']
            if gdict['skiplist'] is not None:
                limiter.skip = gdict['skiplist'].split(',')
            action = string_to_actioncode(gdict['action'])
            if action is None:
                self.logger.error("Limiter config line %s : invalid action %s"%(lineno,gdict['action']))
            limiter.action=action
            limiter.message=gdict['message']
            limiters.append(limiter)
        return limiters


    def examine(self,suspect):
        if self.limiters is None:
            filename=self.config.get(self.section,'limiterfile')
            if not os.path.exists(filename):
                self.logger.error("Limiter config file %s not found"%filename)
                return
            with open(filename) as fp:
                limiterconfig = fp.read()
            limiters = self.load_limiter_config(limiterconfig)
            self.limiters = limiters
            self.logger.info("Found %s limiter configurations"%(len(limiters)))

        if self.backend_instance is None:
            btype = self.config.get(self.section,'backendtype')
            if btype not in AVAILABLE_RATELIMIT_BACKENDS:
                self.logger.error('ratelimit backend %s not available'%(btype))
                return
            self.backend_instance = AVAILABLE_RATELIMIT_BACKENDS[btype](self.config.get(self.section,'backendconfig'))


        skiplist = []
        for limiter in self.limiters:
            if limiter.name in skiplist: # check if this limiter is skipped by a previous one
                self.logger.debug('limiter %s skipped due to previous match'%limiter.name)
                continue

            #get field values
            allfieldsavailable=True
            fieldvalues=[]
            for fieldname in limiter.fields:
                if hasattr(suspect, fieldname):
                    fieldvalues.append(getattr(suspect, fieldname))
                else:
                    allfieldsavailable = False
                    self.logger.debug('Skipping limiter %s - field %s not available'%(limiter.name,fieldname))
                    break
            if not allfieldsavailable: #rate limit can not be applied
                continue

            checkval = ','.join(fieldvalues)
            if limiter.regex is not None:
                if re.match(limiter.regex,checkval):
                    if limiter.skip is not None:
                        skiplist.extend(limiter.skip)
                else: #no match, skip this limiter
                    self.logger.debug('Skipping limiter %s - regex does not match'%(limiter.name))
                    continue
            #self.logger.debug("check %s"%str(limiter))
            eventname = limiter.name+checkval
            timespan = limiter.timespan
            max = limiter.max
            if max < 0: #no limit
                continue
            event_count = self.backend_instance.check_count(eventname,timespan)
            self.logger.debug("Limiter event %s  count: %s"%(eventname,event_count))
            if event_count>max:
                return limiter.action, apply_template( limiter.message, suspect)

