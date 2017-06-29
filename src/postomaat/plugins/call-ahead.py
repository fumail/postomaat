#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys

#in case the tool is not installed system wide (development...)
if __name__ =='__main__':
    sys.path.append('../../')

from postomaat.shared import ScannerPlugin, DUNNO, REJECT, strip_address, extract_domain, get_config, string_to_actioncode
from postomaat.db import SQLALCHEMY_AVAILABLE,get_session
from postomaat.dnsquery import HAVE_DNS, lookup, mxlookup
import smtplib
from string import Template
import logging
from datetime import datetime, timedelta
import re

try:
    import redis
    HAVE_REDIS=True
except ImportError:
    redis = None
    HAVE_REDIS=False

DATEFORMAT = u'%Y-%m-%d %H:%M:%S'

RE_IPV4 = re.compile(
    """(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)""")
RE_IPV6 = re.compile(
    """(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))""")



class AddressCheck(ScannerPlugin):
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger = self._logger()
        self.cache = None
        self.requiredvars={
            'dbconnection':{
                'default':"mysql://root@localhost/callahead?charset=utf8",
                'description':'SQLAlchemy Connection string',
            },
            
            'redis':{
                'default':'127.0.0.1:6379:1',
                'description':'the redis database connection: host:port:dbid',
            },
            
            'redis_timeout':{
                'default':'2',
                'description':'timeout in seconds',
            },
            
            'cache_storage':{
                'default':'sql',
                'description':'the storage backend, either sql or redis',
            },
             
            'always_assume_rec_verification_support':{
                'default': "False",
                'description': """set this to true to disable the blacklisting of servers that don't support recipient verification"""

            }, 
                           
            'always_accept':{
                'default': "False",
                'description': """Set this to always return 'DUNNO' but still perform the recipient check and fill the cache (learning mode without rejects)"""

            },
                           
            'keep_positive_history_time':{
                'default': 30,
                'description': """how long should expired positive cache data be kept in the table history [days] (sql only)"""

            },
                           
            'keep_negative_history_time':{
                'default': 1,
                'description': """how long should expired negative cache data be kept in the table history [days] (sql only)"""

            },
                             
        }
    
    
    
    def _init_cache(self, config):
        if self.cache is None:
            storage = config.get(self.section, 'cache_storage')
            if storage == 'sql':
                self.cache = MySQLCache(config)
            elif storage == 'redis':
                host, port, db = config.get(self.section, 'redis').split(':')
                red = redis.StrictRedis(
                    host=host,
                    port=port,
                    db=int(db),
                    socket_timeout=config.getint(self.section, 'redis_timeout'))
                self.cache = RedisCache(config, red)

        
        
    def lint(self):
        if not SQLALCHEMY_AVAILABLE:
            print "sqlalchemy is not installed"
            return False
        
        if not self.checkConfig():
            return False

        if self.config.get('ca_default', 'server').startswith('mx:') and not HAVE_DNS:
            print "no DNS resolver library available - required for mx resolution"
            return False
        elif not HAVE_DNS:
            print "no DNS resolver library available - some functionality will not be available"
        
        if self.config.get(self.section, 'cache_storage') == 'redis' and not HAVE_REDIS:
            print 'redis backend configured but redis python module not available'
            return False
        
        self._init_cache(self.config)
        
        try:
            poscount, negcount = self.cache.get_total_counts()
            print "Addresscache: %s positive entries, %s negative entries"%(poscount,negcount)
        except Exception as e:
            print "DB Connection failed: %s"%str(e)
            return False
        
        test = SMTPTest(self.config)
        try:
            timeout = float(test.get_domain_config('lint', 'timeout'))
            #print 'Using default config timeout: %ss' % timeout
        except Exception:
            print 'Could not get timeout value from config, using internal default of 10s'
            
        try:
            dbconnection = self.config.get(self.section, 'dbconnection')
            conn=get_session(dbconnection)
            conn.execute("SELECT 1")
        except Exception as e:
            print "Failed to connect to SQL database: %s" % str(e)
            
        return True
    
    
    
    def __str__(self):
        return "Address Check"
    
    
    
    def examine(self,suspect):
        from_address=suspect.get_value('sender')
        if from_address is None:
            self.logger.error('No FROM address found')
            return DUNNO
      
        address=suspect.get_value('recipient')
        if address is None:
            self.logger.error('No TO address found')
            return DUNNO
        
        address=strip_address(address)
        from_address=strip_address(from_address)
        
        #check cache
        self._init_cache(self.config)
        try:
            entry=self.cache.get_address(address)
        except Exception as e:
            self.logger.error('Could not connect to cache database: %s' % str(e))
            return DUNNO

        if entry is not None:
            positive, message = entry
            
            if positive:
                self.logger.info('accepting cached address %s'%address)
                return DUNNO,None
            else:
                if self.config.getboolean(self.section,'always_accept'):
                    self.logger.info('Learning mode - accepting despite negative cache entry')
                else:
                    self.logger.info('rejecting negative cached address %s : %s'%(address,message))
                    return REJECT,"previously cached response:%s"%message
        
        #load domain config
        domain=extract_domain(address)
        domainconfig=MySQLConfigBackend(self.config).get_domain_config_all(domain)

        if domainconfig is None:
            self.logger.debug('Domainconfig for domain %s was empty' % domain)
            return DUNNO
        
        #enabled?
        test=SMTPTest(self.config)
        servercachetime = test.get_domain_config(domain, 'test_server_interval', domainconfig)

        enabled=int(test.get_domain_config(domain, 'enabled', domainconfig))
        if not enabled:
            self.logger.info('%s: call-aheads for domain %s are disabled'%(address,domain))
            return DUNNO,None
        
        #check blacklist
        relays=test.get_relays(domain,domainconfig)
        testaddress=test.maketestaddress(domain)
        if relays is None or len(relays)==0:
            self.logger.error("No relay for domain %s found!"%domain)
            relay = None
            result = SMTPTestResult()
            result.state=SMTPTestResult.TEST_FAILED
            result.errormessage="no relay for domain %s found" % domain
        
        else:
            relay=relays[0]
            self.logger.debug("Testing relay %s for domain %s"%(relay,domain))
            if self.cache.is_blacklisted(domain, relay):
                self.logger.info('%s: server %s for domain %s is blacklisted for call-aheads, skipping'%(address,relay,domain))
                return DUNNO,None
        
            #make sure we don't call-ahead ourself
            if address==testaddress:
                self.logger.error("Call-ahead loop detected!")
                self.cache.blacklist(domain, relay, servercachetime, SMTPTestResult.STAGE_CONNECT, 'call-ahead loop detected')
                return DUNNO,None
            
            #perform call-ahead
            sender=test.get_domain_config(domain, 'sender', domainconfig, {'bounce':'','originalfrom':from_address})
            try:
                timeout = float(test.get_domain_config(domain, 'timeout', domainconfig))
            except (ValueError, TypeError):
                timeout = 10
            use_tls=int(test.get_domain_config(domain, 'use_tls', domainconfig))
            result=test.smtptest(relay,[address,testaddress],mailfrom=sender, timeout=timeout, use_tls=use_tls)
        
        
        if result.state != SMTPTestResult.TEST_OK:
            action = DUNNO
            message = None
            
            for stage in [SMTPTestResult.STAGE_PRECONNECT, SMTPTestResult.STAGE_RESOLVE, SMTPTestResult.STAGE_CONNECT, SMTPTestResult.STAGE_HELO, SMTPTestResult.STAGE_MAIL_FROM, SMTPTestResult.STAGE_RCPT_TO]:
                if result.stage == stage:
                    stageaction, message, interval = self._get_stage_config(stage, test, domain, domainconfig)
                    if stageaction is not None:
                        action = stageaction
                    if interval is not None:
                        servercachetime = min(servercachetime, interval)
            
            if relay is not None:
                self.logger.error('Problem testing recipient verification support on server %s : %s. putting on blacklist.'%(relay,result.errormessage))
                self.cache.blacklist(domain, relay, servercachetime, result.stage, result.errormessage)
            return action, message
        
        addrstate,code,msg=result.rcptoreplies[testaddress]
        recverificationsupport=None
        blreason='unknown'
        if addrstate==SMTPTestResult.ADDRESS_OK:
            blreason='accepts any recipient'
            recverificationsupport=False
        elif addrstate==SMTPTestResult.ADDRESS_TEMPFAIL:
            blreason='temporary failure: %s %s'%(code,msg)
            recverificationsupport=False
        elif addrstate==SMTPTestResult.ADDRESS_DOES_NOT_EXIST:
            recverificationsupport=True
        
        #override: ignore recipient verification fail
        if self.config.getboolean(self.section,'always_assume_rec_verification_support'):
            recverificationsupport=True
        
        if recverificationsupport:
            addrstate,code,msg=result.rcptoreplies[address]
            positive=True
            cachetime=test.get_domain_config(domain, 'positive_cache_time', domainconfig)
            
            #handle case where testadress got 5xx , but actual address got 4xx
            if addrstate==SMTPTestResult.ADDRESS_TEMPFAIL:
                self.logger.info('Server %s for domain %s: blacklisting for %s seconds (tempfail: %s)'%(relay,domain,servercachetime,msg))
                self.cache.blacklist(domain, relay, servercachetime, result.stage, 'tempfail: %s'%msg)
                return DUNNO,None
            
            if addrstate==SMTPTestResult.ADDRESS_DOES_NOT_EXIST:
                positive=False
                cachetime=test.get_domain_config(domain, 'negative_cache_time', domainconfig)
            
            self.cache.put_address(address,cachetime,positive,msg)
            neg=""
            if not positive:
                neg="negative "
            self.logger.info("%scached %s for %s seconds (%s)"%(neg,address,cachetime,msg))
            
            if positive:
                return DUNNO,None
            else:
                if self.config.getboolean(self.section,'always_accept'):
                    self.logger.info('Learning mode - accepting despite inexistent address')
                else:
                    return REJECT,msg
            
        else:
            self.logger.info('Server %s for domain %s: blacklisting for %s seconds (%s) in stage %s'%(relay,domain,servercachetime,blreason, result.stage))
            self.cache.blacklist(domain, relay, servercachetime, result.stage, blreason)
        return DUNNO,None
    
    
    
    def _get_stage_config(self, stage, test, domain, domainconfig):
        try:
            interval = int(test.get_domain_config(domain, '%s_fail_interval' % stage, domainconfig))
        except (ValueError, TypeError):
            interval = None
            self.logger.debug('Invalid %s_fail_interval for domain %s' % (stage, domain))
        stageaction = string_to_actioncode(test.get_domain_config(domain, '%s_fail_action' % stage, domainconfig))
        message = test.get_domain_config(domain, '%s_fail_message' % stage, domainconfig) or None
        
        return stageaction, message, interval
    

class SMTPTestResult(object):
    STAGE_PRECONNECT="preconnect"
    STAGE_RESOLVE="resolve"
    STAGE_CONNECT="connect"
    STAGE_HELO="helo"
    STAGE_MAIL_FROM="mail_from"
    STAGE_RCPT_TO="rcpt_to"
    
    TEST_IN_PROGRESS=0
    TEST_FAILED=1
    TEST_OK=2
    
    ADDRESS_OK=0
    ADDRESS_DOES_NOT_EXIST=1
    ADDRESS_TEMPFAIL=2
    ADDRESS_UNKNOWNSTATE=3
    
    def __init__(self):
        #at what stage did the test end
        self.stage=SMTPTestResult.STAGE_PRECONNECT
        #test ok or error
        self.state=SMTPTestResult.TEST_IN_PROGRESS    
        self.errormessage=None 
        self.relay=None
        
        #replies from smtp server
        #tuple: (code,text)
        self.banner=None
        self.heloreply=None
        self.mailfromreply=None
        
        #address verification
        #tuple: (ADDRESS_STATUS,code,text)
        self.rcptoreplies={}
    
    def __str__(self):
        str_status="in progress"
        if self.state==SMTPTestResult.TEST_FAILED:
            str_status="failed"
        elif self.state==SMTPTestResult.TEST_OK:
            str_status="ok"
        
        str_stage="unknown"    
        stagedesc={
            SMTPTestResult.STAGE_PRECONNECT:"preconnect",
            SMTPTestResult.STAGE_RESOLVE:"resolve",
            SMTPTestResult.STAGE_CONNECT:'connect',
            SMTPTestResult.STAGE_HELO:'helo',
            SMTPTestResult.STAGE_MAIL_FROM:'mail_from',
            SMTPTestResult.STAGE_RCPT_TO:'rcpt_to'
        }
        if self.stage in stagedesc:
            str_stage=stagedesc[self.stage]
            
        desc="TestResult: relay=%s status=%s stage=%s"%(self.relay,str_status,str_stage)
        if self.state==SMTPTestResult.TEST_FAILED:
            desc="%s error=%s"%(desc,self.errormessage)
            return desc
        
        addrstatedesc={
            SMTPTestResult.ADDRESS_DOES_NOT_EXIST:'no',
            SMTPTestResult.ADDRESS_OK:'yes',
            SMTPTestResult.ADDRESS_TEMPFAIL:'no (temp fail)',
            SMTPTestResult.ADDRESS_UNKNOWNSTATE:'unknown'
        }
        
        for k in self.rcptoreplies:
            v=self.rcptoreplies[k]
            statedesc=addrstatedesc[v[0]]
            
            desc="%s\n %s: accepted=%s code=%s (%s)"%(desc,k,statedesc,v[1],v[2])
            
        return desc

class SMTPTest(object):
    def __init__(self,config=None):
        self.config=config
        self.logger=logging.getLogger('postomaat.smtptest')
        
    
    def is_ip(self, value):
        return RE_IPV4.match(value) or RE_IPV6.match(value)
    
    
    def maketestaddress(self,domain):
        """Return a static test address that probably doesn't exist. It is NOT randomly generated, so we can check if the incoming connection does not produce a call-ahead loop""" 
        return "rbxzg133-7tst@%s"%domain
    
    
    def get_domain_config(self,domain,key,domainconfig=None,templatedict=None):
        """Get configuration value for domain or default. Apply template string if templatedict is not None"""
        defval=self.config.get('ca_default',key)
        
        theval=defval
        if domainconfig is None: #nothing from sql
            #check config file overrides
            configbackend=ConfigFileBackend(self.config)
            
            #ask the config backend if we have a special server config
            backendoverride=configbackend.get_domain_config_value(domain, key)
            if backendoverride is not None:
                theval=backendoverride
        elif key in domainconfig:
            theval=domainconfig[key]
        
        if templatedict is not None:
            theval=Template(theval).safe_substitute(templatedict) 
        
        return theval
    
    def get_relays(self,domain,domainconfig=None):
        """Determine the relay(s) for a domain"""
        serverconfig=self.get_domain_config(domain, 'server', domainconfig,{'domain':domain})

        (tp,val)=serverconfig.split(':',1)
        
        if tp=='sql':
            conn=get_session(self.config.get('AddressCheck','dbconnection'))
            ret=conn.execute(val)
            arr= [result[0] for result in ret]
            conn.remove()
            return arr
        elif tp=='mx':
            return mxlookup(val)
        elif tp=='static':
            return [val,]
        elif tp=='txt':
            try:
                with open(val) as fp:
                    lines=fp.readlines()
                for line in lines:
                    fdomain,ftarget=line.split()
                    if domain.lower()==fdomain.lower():
                        return [ftarget,]
            except Exception as e:
                self.logger.error("Txt lookup failed: %s"%str(e))
        else:
            self.logger.error('unknown relay lookup type: %s'%tp)
            return None 
        
    
    def smtptest(self,relay,addrlist,helo=None,mailfrom=None,timeout=10, use_tls=1):
        """perform a smtp check until the rcpt to stage
        returns a SMTPTestResult
        """
        result=SMTPTestResult()
        result.relay=relay
        
        if mailfrom is None:
            mailfrom=""
            
        result.stage=SMTPTestResult.STAGE_RESOLVE
        if HAVE_DNS and not self.is_ip(relay):
            arecs = lookup(relay)
            if arecs is not None and len(arecs)==0:
                result.state=SMTPTestResult.TEST_FAILED
                result.errormessage="relay %s could not be resolved" % relay
                return result
        

        result.stage=SMTPTestResult.STAGE_CONNECT
        smtp=smtplib.SMTP(local_hostname=helo)
        smtp.timeout=timeout
        #smtp.set_debuglevel(True)
        try:
            code,msg=smtp.connect(relay, 25)
            result.banner=(code,msg)
            if code<200 or code>299:
                result.state=SMTPTestResult.TEST_FAILED
                result.errormessage="connection was not accepted: %s"%msg
                return result
        except Exception as e:
            result.errormessage=str(e)
            result.state=SMTPTestResult.TEST_FAILED
            return result
        
        
        #HELO
        result.stage=SMTPTestResult.STAGE_HELO
        try:
            code,msg=smtp.ehlo()
            result.heloreply=(code,msg)
            if code>199 and code<300:
                if smtp.has_extn('STARTTLS') and use_tls:
                    code,msg = smtp.starttls()
                    if code>199 and code<300:
                        code,msg=smtp.ehlo()
                        if code<200 or code>299:
                            result.state=SMTPTestResult.TEST_FAILED
                            result.errormessage="EHLO after STARTTLS was not accepted: %s"%msg
                            return result
                    else:
                        self.logger.info('relay %s did not accept starttls: %s %s' % (relay, code, msg))
                else:
                    self.logger.info('relay %s does not support starttls: %s %s' % (relay, code, msg))
            else:
                self.logger.info('relay %s does not support esmtp, falling back' % (relay))
                code,msg=smtp.helo()
                if code < 200 or code > 299:
                    result.state = SMTPTestResult.TEST_FAILED
                    result.errormessage = "HELO was not accepted: %s" % msg
                    return result
        except Exception as e:
            result.errormessage=str(e)
            result.state=SMTPTestResult.TEST_FAILED
            return result
        
        #MAIL FROM
        result.stage=SMTPTestResult.STAGE_MAIL_FROM
        try:
            code,msg=smtp.mail(mailfrom)
            result.mailfromreply=(code,msg)
            if code<200 or code>299:
                result.state=SMTPTestResult.TEST_FAILED
                result.errormessage="MAIL FROM was not accepted: %s"%msg
                return result
        except Exception as e:
            result.errormessage=str(e)
            result.state=SMTPTestResult.TEST_FAILED
            return result

        #RCPT TO
        result.stage=SMTPTestResult.STAGE_RCPT_TO
        try:
            for addr in addrlist:
                code,msg=smtp.rcpt(addr)
                if code>199 and code<300:
                    addrstate=SMTPTestResult.ADDRESS_OK
                elif code>399 and code <500:
                    addrstate=SMTPTestResult.ADDRESS_TEMPFAIL
                elif code>499 and code <600:
                    addrstate=SMTPTestResult.ADDRESS_DOES_NOT_EXIST
                else:
                    addrstate=SMTPTestResult.ADDRESS_UNKNOWNSTATE
                
                putmsg="relay %s said:%s"%(relay,msg)
                result.rcptoreplies[addr]=(addrstate,code,putmsg)
        except Exception as e:
            result.errormessage=str(e)
            result.state=SMTPTestResult.TEST_FAILED
            return result
         
        result.state=SMTPTestResult.TEST_OK
        
        try:
            smtp.quit()
        except Exception as e:
            pass
        return result   



class CallAheadCacheInterface(object):
    def __init__(self,config):
        self.config=config
        self.logger=logging.getLogger('postomaat.call-ahead.%s'%self.__class__.__name__)
    
    def blacklist(self,domain,relay,expires,failstage=SMTPTestResult.STAGE_RCPT_TO,reason='unknown'):
        """Put a domain/relay combination on the recipient verification blacklist for a certain amount of time"""
        self.logger.error('blacklist:not implemented')
    
    def is_blacklisted(self,domain,relay):
        """Returns True if the server/relay combination is currently blacklisted and should not be used for recipient verification"""
        self.logger.error('is_blacklisted: not implemented')
        return False
    
    def get_blacklist(self):
        """return all blacklisted servers"""
        self.logger.error('get_blacklist: not implemented')
        #expected format per item: domain, relay, reason, expiry timestamp
        return []
    
    def unblacklist(self,relayordomain):
        """remove a server from the blacklist/history"""
        self.logger.error('unblacklist: not implemented')
        return 0
    
    def wipe_domain(self,domain,positive=None):
        self.logger.error('wipe_domain: not implemented')
        return 0
    
    def get_all_addresses(self,domain):
        self.logger.error('get_all_addresses: not implemented')
        return []
    
    def put_address(self,address,expires,positiveEntry=True,message=None):
        """add address to cache"""
        self.logger.error('put_address: not implemented')
    
    def get_address(self,address):
        """Returns a tuple (positive(boolean),message) if a cache entry exists, None otherwise"""
        self.logger.error('get_address: not implemented')
        return None
    
    def wipe_address(self,address):
        """remove address from cache"""
        self.logger.error('wipe_address: not implemented')
        return 0
    
    def get_total_counts(self):
        self.logger.error('get_total_counts: not implemented')
        return 0, 0
    
    def cleanup(self):
        self.logger.error('cleanup: not implemented')
        return 0, 0, 0
    
    
    
class MySQLCache(CallAheadCacheInterface):
    def __init__(self,config):
        CallAheadCacheInterface.__init__(self, config)
    
    def blacklist(self,domain,relay,seconds,failstage='rcpt_to',reason='unknown'):
        """Put a domain/relay combination on the recipient verification blacklist for a certain amount of time"""
        conn=get_session(self.config.get('AddressCheck','dbconnection'))

        statement="""INSERT INTO ca_blacklist (domain,relay,expiry_ts,check_stage,reason)
                    VALUES (:domain,:relay,now()+interval :interval second,:check_stage,:reason)
                    ON DUPLICATE KEY UPDATE expiry_ts=GREATEST(expiry_ts,now()+interval :interval second),check_stage=:check_stage,reason=:reason
                    """
        values={
                'domain':domain,
                'relay':relay,
                'interval':seconds,
                'check_stage':failstage,
                'reason':reason,
                }
        res=conn.execute(statement,values)
        conn.remove()
            
    def is_blacklisted(self,domain,relay):
        """Returns True if the server/relay combination is currently blacklisted and should not be used for recipient verification"""
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        if not conn:
            return False
        statement="SELECT reason FROM ca_blacklist WHERE domain=:domain and relay=:relay and expiry_ts>now()"
        values={'domain':domain,'relay':relay}
        sc=conn.execute(statement,values).scalar()
        conn.remove()
        return sc
        
    def unblacklist(self,relayordomain):
        """remove a server from the blacklist/history"""
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        statement="""DELETE FROM ca_blacklist WHERE domain=:removeme or relay=:removeme"""
        values={'removeme':relayordomain}
        res=conn.execute(statement,values)
        rc=res.rowcount
        conn.remove()
        return rc
       
    def get_blacklist(self):
        """return all blacklisted servers"""
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        if not conn:
            return None
        statement="SELECT domain,relay,reason,expiry_ts FROM ca_blacklist WHERE expiry_ts>now() ORDER BY domain"
        values={}
        result=conn.execute(statement,values)
        ret=[row for row in result]
        conn.remove()
        return ret
        
    def wipe_address(self,address):
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        if not conn:
            return
        statement="""DELETE FROM ca_addresscache WHERE email=:email"""
        values={'email':address}
        res=conn.execute(statement,values)
        rc= res.rowcount
        conn.remove()
        return rc
    
    def cleanup(self):
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        postime=self.config.getint('AddressCheck','keep_positive_history_time')
        negtime=self.config.getint('AddressCheck','keep_negative_history_time')
        statement="""DELETE FROM ca_addresscache WHERE positive=:pos and expiry_ts<(now() -interval :keeptime day)"""
        
        res=conn.execute(statement,dict(pos=0,keeptime=negtime))
        negcount=res.rowcount
        res=conn.execute(statement,dict(pos=1,keeptime=postime))
        poscount=res.rowcount
        
        res=conn.execute("""DELETE FROM ca_blacklist where expiry_ts<now()""")
        blcount=res.rowcount
        conn.remove()
        return poscount,negcount,blcount
        
    def wipe_domain(self,domain,positive=None):
        """wipe all cache info for a domain. 
        if positive is None(default), all cache entries are deleted. 
        if positive is False all negative cache entries are deleted
        if positive is True, all positive cache entries are deleted
        """
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        if not conn:
            return
        
        posstatement=""
        if positive==True:
            posstatement="and positive=1"
        if positive==False:
            posstatement="and positive=0"
        
        statement="""DELETE FROM ca_addresscache WHERE domain=:domain %s"""%posstatement
        values={'domain':domain}
        res=conn.execute(statement,values)
        rc= res.rowcount
        conn.remove()
        return rc
        
    def put_address(self,address,seconds,positiveEntry=True,message=None):
        """put address into the cache"""
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        if not conn:
            return
        statement="""INSERT INTO ca_addresscache (email,domain,expiry_ts,positive,message) VALUES (:email,:domain,now()+interval :interval second,:positive,:message)
        ON DUPLICATE KEY UPDATE check_ts=now(),expiry_ts=GREATEST(expiry_ts,now()+interval :interval second),positive=:positive,message=:message
        """
        domain=extract_domain(address)
        values={'email':address,
                'domain':domain,
                'interval':seconds,
                'positive':positiveEntry,
                'message':message,
            }
        conn.execute(statement,values)
        conn.remove()
    
    
    def get_address(self,address):
        """Returns a tuple (positive(boolean),message) if a cache entry exists, None otherwise"""
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        if not conn:
            return
        statement="SELECT positive,message FROM ca_addresscache WHERE email=:email and expiry_ts>now()"
        values={'email':address}
        res=conn.execute(statement,values)
        first= res.first()
        conn.remove()
        return first
     
    def get_all_addresses(self,domain):
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        if not conn:
            return None
        statement="SELECT email,positive FROM ca_addresscache WHERE domain=:domain and expiry_ts>now() ORDER BY email"
        values={'domain':domain}
        result=conn.execute(statement,values)
        ret=[x for x in result]
        conn.remove()
        return ret
    
    def get_total_counts(self):
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        statement="SELECT count(*) FROM ca_addresscache WHERE expiry_ts>now() and positive=1"
        result=conn.execute(statement)
        poscount=result.fetchone()[0]
        statement="SELECT count(*) FROM ca_addresscache WHERE expiry_ts>now() and positive=0"
        result=conn.execute(statement)
        negcount=result.fetchone()[0]
        conn.remove()
        return poscount, negcount
     
    
     
class RedisCache(CallAheadCacheInterface):
    
    def __init__(self, config, redisconn=None):
        CallAheadCacheInterface.__init__(self, config)
        self.redis = redisconn or redis.StrictRedis()
        
        
        
    def _update(self, name, values, ttl):
        """atomic update of hash value and ttl in redis"""
        pipe = self.redis.pipeline()
        pipe.hmset(name, values)
        pipe.expire(name, ttl)
        pipe.execute()
        
        
    
    def _multiget(self, names, keys):
        """atomically gets multiple hashes from redis"""
        pipe = self.redis.pipeline()
        for name in names:
            pipe.hmget(name, keys)
        items = pipe.execute()
        return items
    
    
    
    def __pos2bool(self, entry, idx):
        """converts string boolean value in list back to boolean"""
        if entry is None or len(entry)<idx:
            pass
        if entry[idx] == 'True':
            entry[idx] = True
        elif entry[idx] == 'False':
            entry[idx] = False
        
        
    
    def blacklist(self,domain,relay,expires,failstage=SMTPTestResult.STAGE_RCPT_TO,reason='unknown'):
        """Put a domain/relay combination on the recipient verification blacklist for a certain amount of time"""
        name = 'relay-%s-%s' % (relay, domain)
        values = {
            'domain':domain,
            'relay':relay,
            'check_stage':failstage,
            'reason':reason,
            'check_ts':datetime.now().strftime(DATEFORMAT),
        }
        expires = max(expires, self.redis.ttl(name))
        self._update(name, values, expires)
        
        
        
    def unblacklist(self,relayordomain):
        """remove a server from the blacklist/history"""
        names = self.redis.keys('relay-*%s*' % relayordomain)
        if names:
            delcount = self.redis.delete(*names)
        else:
            delcount = 0
        return delcount
        
        
    
    def is_blacklisted(self,domain,relay):
        """Returns True if the server/relay combination is currently blacklisted and should not be used for recipient verification"""
        name = 'relay-%s-%s' % (relay, domain)
        blacklisted = self.redis.exists(name)
        return blacklisted
    
    
    
    def get_blacklist(self):
        """return all blacklisted servers"""
        names = self.redis.keys('relay-*')
        items = []
        for name in names:
            item = self.redis.hmget(name, ['domain', 'relay', 'reason'])
            ttl = self.redis.ttl(name)
            ts = datetime.now() + timedelta(seconds=ttl)
            item.append(ts.strftime(DATEFORMAT))
            items.append(item)
        items.sort(key=lambda x:x[0])
        return items
    
    
    
    def wipe_domain(self,domain,positive=None):
        """remove all addresses in given domain from cache"""
        if positive is not None:
            positive = positive.lower()
        names = self.redis.keys('addr-*@%s' % domain)
        
        if positive is None or positive == 'all':
            delkeys = names
        else:
            entries = self._multiget(names, ['address', 'positive'])
            delkeys = []
            for item in entries:
                if positive == 'positive' and item[1] == 'True':
                    delkeys.append('addr-%s' % item['address'])
                elif positive == 'negative' and item[1] == 'False':
                    delkeys.append('addr-%s' % item['address'])
            
        if delkeys:
            delcount = self.redis.delete(*delkeys)
        else:
            delcount = 0
        return delcount
    
    
    
    def get_all_addresses(self,domain):
        """get all addresses in given domain from cache"""
        names = self.redis.keys('addr-*@%s' % domain)
        entries = self._multiget(names, ['address', 'positive'])
        for item in entries:
            self.__pos2bool(item, 1)
        return entries
    
    
    
    def put_address(self,address,expires,positiveEntry=True,message=None):
        """put address in cache"""
        name = 'addr-%s' % address
        domain=extract_domain(address)
        values={
            'address':address,
            'domain':domain,
            'positive':positiveEntry,
            'message':message,
            'check_ts':datetime.now().strftime(DATEFORMAT),
        }
        expires = max(expires, self.redis.ttl(name))
        self._update(name, values, expires)
        
        
    
    def get_address(self,address):
        """Returns a tuple (positive(boolean),message) if a cache entry exists, None otherwise"""
        name = 'addr-%s' % address
        entry = self.redis.hmget(name, ['positive', 'message'])
        if entry[0] is not None:
            self.__pos2bool(entry, 0)
        else:
            entry = None
        return entry
        
        
        
    def wipe_address(self,address):
        """remove given address from cache"""
        name = self.redis.keys('addr-%s' % address)
        delcount = self.redis.delete(name)
        return delcount
    
    
    
    def get_total_counts(self):
        """return how many positive and negative entries are in cache"""
        names = self.redis.keys('addr-*')
        entries = self._multiget(names, ['positive'])
        poscount = negcount = 0
        for item in entries:
            if item[0] == 'True':
                poscount += 1
            else:
                negcount += 1
        return poscount, negcount
    
    
    
    def cleanup(self):
        # nothing to do on redis
        return 0, 0, 0
        
 
    
class ConfigBackendInterface(object):
    def __init__(self,config):
        self.logger=logging.getLogger('postomaat.call-ahead.%s'%self.__class__.__name__)
        self.config=config
    
    def get_domain_config_value(self,domain,key):
        """return a single config value for this domain"""
        self.logger.error("get_domain_config_value: not implemented")
        return None
    
    def get_domain_config_all(self,domain):
        """return all config values for this domain"""
        self.logger.error("get_domain_config_value: not implemented")
        return {}



class MySQLConfigBackend(ConfigBackendInterface):
    def __init__(self,config):
        self.logger=logging.getLogger('postomaat.call-ahead.%s'%self.__class__.__name__)
        ConfigBackendInterface.__init__(self, config)
    
    def get_domain_config_value(self,domain,key):
        sc=None
        try:
            conn=get_session(self.config.get('AddressCheck','dbconnection'))
            res=conn.execute("SELECT confvalue FROM ca_configoverride WHERE domain=:domain and confkey=:confkey",{'domain':domain,'confkey':key})
            sc=res.scalar()
            conn.remove()
        except Exception as e:
            self.logger.error('Could not connect to config SQL database')
        return sc
    
    def get_domain_config_all(self,domain):
        retval=dict()
        try:
            conn=get_session(self.config.get('AddressCheck','dbconnection'))
            res=conn.execute("SELECT confkey,confvalue FROM ca_configoverride WHERE domain=:domain",{'domain':domain})
            for row in res:
                retval[row[0]]=row[1]
            conn.remove()
        except Exception as e:
            self.logger.error('Could not connect to config SQL database')
        return retval



class ConfigFileBackend(ConfigBackendInterface):
    """Read domain overrides directly from postomaat config, using ca_<domain> sections"""
    def __init__(self,config):
        ConfigBackendInterface.__init__(self, config)
        
    def get_domain_config_value(self,domain,key):
        if self.config.has_option('ca_%s'%domain,key):
            return self.config.get('ca_%s'%domain,key)
        return None
        


class SMTPTestCommandLineInterface(object):
    def __init__(self):
        self.cache = None
        self.section = 'AddressCheck'
        
        self.commandlist={
            'put-address':self.put_address,
            'wipe-address':self.wipe_address,
            'wipe-domain':self.wipe_domain,
            'cleanup':self.cleanup,
            'test-dry':self.test_dry,
            'test-config':self.test_config,
            'update':self.update,
            'help':self.help,
            'show-domain':self.show_domain,
            'devshell':self.devshell,
            'show-blacklist':self.show_blacklist,
            'unblacklist':self.unblacklist,
        }
    
    

    def _init_cache(self, config):
        if self.cache is None:
            storage = config.get(self.section, 'cache_storage')
            if storage == 'sql':
                self.cache = MySQLCache(config)
            elif storage == 'redis':
                host, port, db = config.get(self.section, 'redis').split(':')
                red = redis.StrictRedis(
                    host=host,
                    port=port,
                    db=int(db),
                    socket_timeout = config.getint(self.section, 'redis_timeout'))
                self.cache = RedisCache(config, red)
                
                
    
    def cleanup(self,*args):
        config=get_config()
        self._init_cache(config)
        poscount, negcount, blcount = self.cache.cleanup()
        if 'verbose' in args:
            print "Removed %s positive,%s negative records from history data"%(poscount,negcount)
            print "Removed %s expired relays from call-ahead blacklist"%blcount
    
    
    
    def devshell(self):
        """Drop into a python shell for debugging"""
        import readline
        import code
        logging.basicConfig(level=logging.DEBUG)
        cli=self
        from postomaat.shared import get_config
        config=get_config('../../../conf/postomaat.conf.dist', '../../../conf/conf.d')
        config.read('../../../conf/conf.d/call-ahead.conf.dist')
        self._init_cache(config)
        plugin=AddressCheck(config)
        print "cli : Command line interface class"
        print "sqlcache : SQL cache backend"
        print "plugin: AddressCheck Plugin"
        terp=code.InteractiveConsole(locals())
        terp.interact("")
    
    
    
    def help(self,*args):
        myself=sys.argv[0]
        print "usage:"
        print "%s <command> [args]"%myself
        print ""
        print "Available commands:"
        commands=[
            ("test-dry","<server> <emailaddress> [<emailaddress>] [<emailaddress>]","test recipients on target server using the null-sender, does not use any config or caching data"),
            ("test-config","<emailaddress>","test configuration using targetaddress <emailaddress>. shows relay lookup and target server information"),
            ("update","<emailaddress>","test & update server state&address cache for <emailaddress>"),
            ("put-address","<emailaddress> <positive|negative> <ttl> <message>","add <emailaddress> to the cache"),
            ("wipe-address","<emailaddress>","remove <emailaddress> from the cache/history"),
            ("wipe-domain","<domain> [positive|negative|all (default)]","remove positive/negative/all entries for domain <domain> from the cache/history"),
            ("show-domain","<domain>","list all cache entries for domain <domain>"),
            ("show-blacklist","","display all servers currently blacklisted for call-aheads"),
            ("unblacklist","<relay or domain>","remove relay from the call-ahead blacklist"),
            ("cleanup","[verbose]","clean history data from database. this can be run from cron. add 'verbose' to see how many records where cleared"),
        ]
        for cmd,arg,desc in commands:
            self._print_help(cmd, arg, desc)
        
    def _print_help(self,command,args,description):
        from postomaat.funkyconsole import FunkyConsole
        fc=FunkyConsole()
        bold=fc.MODE['bold']
        cyan=fc.FG['cyan']
        print "%s %s\t%s"%(fc.strcolor(command, [bold,]),fc.strcolor(args,[cyan,]),description)
        
        
    def performcommand(self):
        args=sys.argv
        if len(args)<2:
            print "no command given."
            self.help()
            sys.exit(1)
            
        cmd=args[1]
        cmdargs=args[2:]
        if cmd not in self.commandlist:
            print "command '%s' not implemented. try ./call-ahead help"%cmd
            sys.exit(1)
        
        self.commandlist[cmd](*cmdargs)
        
    def test_dry(self,*args):
        if len(args)<2:
            print "usage: test-dry <server> <address> [...<address>]"
            sys.exit(1)
        server=args[0]
        addrs=args[1:]
        test=SMTPTest()
        
        domain=extract_domain(addrs[0])
        try:
            config=get_config()
            test.config = config
            domainconfig=MySQLConfigBackend(config).get_domain_config_all(domain)
            try:
                timeout = float(test.get_domain_config(domain, 'timeout', domainconfig))
            except (ValueError, TypeError):
                timeout = 10
            use_tls = int(test.get_domain_config(domain, 'use_tls', domainconfig))
        except IOError as e:
            print str(e)
            timeout = 10
            use_tls=1
        
        result=test.smtptest(server,addrs,timeout=timeout, use_tls=use_tls)
        print result
        
    def test_config(self,*args):
        logging.basicConfig(level=logging.INFO)
        if len(args)!=1:
            print "usage: test-config <address>"
            sys.exit(1)
        address=args[0]
        
        domain=extract_domain(address)
        
        config=get_config()
        domainconfig=MySQLConfigBackend(config).get_domain_config_all(domain)
        
        print "Checking address cache..."
        self._init_cache(config)
        entry=self.cache.get_address(address)
        if entry is not None:
            positive, message = entry
            tp="negative"
            if positive:
                tp="positive"
            print "We have %s cache entry for %s: %s"%(tp,address,message)
        else:
            print "No cache entry for %s"%address
        
        test=SMTPTest(config)
        relays=test.get_relays(domain,domainconfig) # type: list
        if relays is None:
                print "No relay for domain %s found!"%domain
                sys.exit(1)
        print "Relays for domain %s are %s"%(domain,relays)
        for relay in relays:
            print "Testing relay %s"%relay
            if self.cache.is_blacklisted(domain, relay):
                print "%s is currently blacklisted for call-aheads"%relay
            else:
                print "%s not blacklisted for call-aheads"%relay
            
            print "Checking if server supports verification...."
            
            sender=test.get_domain_config(domain, 'sender', domainconfig, {'bounce':'','originalfrom':''})
            testaddress=test.maketestaddress(domain)
            try:
                timeout = float(test.get_domain_config(domain, 'timeout', domainconfig))
            except (ValueError, TypeError):
                timeout = 10
            use_tls = int(test.get_domain_config(domain, 'use_tls', domainconfig))
            result=test.smtptest(relay,[address,testaddress],mailfrom=sender, timeout=timeout, use_tls=use_tls)
            if result.state!=SMTPTestResult.TEST_OK:
                print "There was a problem testing this server:"
                print result
                continue
                
            
            addrstate,code,msg=result.rcptoreplies[testaddress]
            if addrstate==SMTPTestResult.ADDRESS_OK:
                print "Server accepts any recipient"
            elif addrstate==SMTPTestResult.ADDRESS_TEMPFAIL:
                print "Temporary problem / greylisting detected"
            elif addrstate==SMTPTestResult.ADDRESS_DOES_NOT_EXIST:
                print "Server supports recipient verification"
            
            print result
    
    
    def put_address(self,*args):
        if len(args)<4:
            print "usage: put-address <emailaddress> <positive|negative> <ttl> <message>"
            sys.exit(1)
            
        address=args[0]
        
        strpos=args[1].lower()
        assert strpos in ['positive','negative'],"Additional argument must be 'positive' or 'negative'"
        if strpos=='positive':
            pos=True
        else:
            pos=False
        
        try:
            ttl = int(args[2])
        except (ValueError, TypeError):
            print 'ttl must be an integer'
            sys.exit(1)
            
        message = ' '.join(args[3:])
                
        config=get_config()
        self._init_cache(config)
        self.cache.put_address(address, ttl, pos, message)
        
    
    
    def wipe_address(self,*args):
        if len(args)!=1:
            print "usage: wipe-address <address>"
            sys.exit(1)
        config=get_config()
        self._init_cache(config)
        rowcount = self.cache.wipe_address(args[0])
        print "Wiped %s records"%rowcount
    
    
    def wipe_domain(self,*args):
        if len(args)<1:
            print "usage: wipe-domain <domain> [positive|negative|all (default)]"
            sys.exit(1)
        
        domain=args[0]

        pos=None
        strpos='' 
        if len(args)>1:
            strpos=args[1].lower()
            assert strpos in ['positive','negative','all'],"Additional argument must be 'positive', 'negative' or 'all'"
            if strpos=='positive':
                pos=True
            elif strpos=='negative':
                pos=False
            else:
                pos=None
                strpos=''
            
        config=get_config()
        self._init_cache(config)
        rowcount = self.cache.wipe_domain(domain,pos)
        print "Wiped %s %s records"%(rowcount,strpos)       
    
    
    
    def show_domain(self,*args):
        if len(args)!=1:
            print "usage: show-domain <domain>"
            sys.exit(1)
        config=get_config()
        self._init_cache(config)
        domain=args[0]
        rows = self.cache.get_all_addresses(domain) # type: list
        
        print "Cache for domain %s (-: negative entry, +: positive entry)"%domain
        for row in rows:
            email,positive=row
            if positive:
                print "+ ",email
            else:
                print "- ",email
        total=len(rows)
        print "Total %s cache entries for domain %s"%(total,domain)
    
    
    def show_blacklist(self,*args):
        if len(args)>0:
            print "usage: show-blackist"
            sys.exit(1)
        config=get_config()
        self._init_cache(config)
        rows = self.cache.get_blacklist() # type: list
        
        print "Call-ahead blacklist (domain/relay/reason/expiry):"
        for row in rows:
            domain,relay,reason,exp=row
            print "%s\t%s\t%s\t%s"%(domain,relay,reason,exp)
            
        total=len(rows)
        print "Total %s blacklisted relays"%total
    
    
    def unblacklist(self,*args):
        if len(args)<1:
            print "usage: unblacklist <relay or domain>"
            sys.exit(1)
        relay=args[0]
        config=get_config()
        self._init_cache(config)
        count = self.cache.unblacklist(relay)
        print "%s entries removed from call-ahead blacklist"%count
    
    
    def update(self,*args):
        logging.basicConfig(level=logging.INFO)
        if len(args)!=1:
            print "usage: update <address>"
            sys.exit(1)
        address=args[0]
        
        domain=extract_domain(address)
        
        config=get_config()
        domainconfig=MySQLConfigBackend(config).get_domain_config_all(domain)
        self._init_cache(config)

        test=SMTPTest(config)
        relays=test.get_relays(domain,domainconfig)
        if relays is None:
            print "No relay for domain %s found!"%domain
            sys.exit(1)
        print "Relays for domain %s are %s"%(domain,relays)
        
        relay=relays[0]
        sender=test.get_domain_config(domain, 'sender', domainconfig, {'bounce':'','originalfrom':''})
        testaddress=test.maketestaddress(domain)
        try:
            timeout = float(test.get_domain_config(domain, 'timeout', domainconfig))
        except (ValueError, TypeError):
            timeout = 10
        use_tls = int(test.get_domain_config(domain, 'use_tls', domainconfig))
        result=test.smtptest(relay,[address,testaddress],mailfrom=sender, timeout=timeout, use_tls=use_tls)
        
        servercachetime=test.get_domain_config(domain, 'test_server_interval', domainconfig)
        if result.state!=SMTPTestResult.TEST_OK:
            print "There was a problem testing this server:"
            print result
            print "putting server on blacklist"
            self.cache.blacklist(domain, relay, servercachetime, result.stage, result.errormessage)
            return DUNNO,None
    
    
        addrstate,code,msg=result.rcptoreplies[testaddress]
        recverificationsupport=None
        if addrstate==SMTPTestResult.ADDRESS_OK:
            recverificationsupport=False
        elif addrstate==SMTPTestResult.ADDRESS_TEMPFAIL:
            recverificationsupport=False
        elif addrstate==SMTPTestResult.ADDRESS_DOES_NOT_EXIST:
            recverificationsupport=True
        
        if recverificationsupport:
            
            if self.cache.is_blacklisted(domain, relay):
                print "Server was blacklisted - removing from blacklist"
                self.cache.unblacklist(relay)
                self.cache.unblacklist(domain)
            
            addrstate,code,msg=result.rcptoreplies[address]
            positive=True
            cachetime=test.get_domain_config(domain, 'positive_cache_time', domainconfig)
            if addrstate==SMTPTestResult.ADDRESS_DOES_NOT_EXIST:
                positive=False
                cachetime=test.get_domain_config(domain, 'negative_cache_time', domainconfig)
            
            self.cache.put_address(address,cachetime,positive,msg)
            neg=""
            if not positive:
                neg="negative"
            print "%s cached %s for %s seconds"%(neg,address,cachetime)
        else:
            print "Server accepts any recipient"
            if config.getboolean('AddressCheck','always_assume_rec_verification_support'):
                print "blacklistings disabled in config- not blacklisting"
            else:
                self.cache.blacklist(domain, relay, servercachetime, result.stage, 'accepts any recipient')
                print "Server blacklisted"
            
        
if __name__=='__main__':
    logging.basicConfig()  
    cli=SMTPTestCommandLineInterface()
    cli.performcommand()