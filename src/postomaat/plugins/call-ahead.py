#!/usr/bin/python
import sys

#in case the tool is not installed system wide (development...)
if __name__ =='__main__':
    sys.path.append('../../')

from postomaat.shared import *
from postomaat.db import SQLALCHEMY_AVAILABLE,get_session
from threading import Lock
import time
import smtplib
from string import Template
import logging
import datetime

HAVE_DNSPYTHON=False
try:
    import DNS
    HAVE_DNSPYTHON=True
    DNS.DiscoverNameServers()
    
except ImportError:
    pass


def mxlookup(domain):
    if HAVE_DNSPYTHON:
        mxrecs=[]
        mxrequest = DNS.mxlookup(domain)
        for dataset in mxrequest:
            if type(dataset) == tuple:
                mxrecs.append(dataset)
                
        mxrecs.sort() #automatically sorts by priority
        return [x[1] for x in mxrecs]
    
    #TODO: other dns libraries?
    
    return None


class AddressCheck(ScannerPlugin):
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.cache=MySQLCache(config)
        self.requiredvars={
            'dbconnection':{
                'default':"mysql://root@localhost/callahead?charset=utf8",
                'description':'SQLAlchemy Connection string',
            },
             
            'always_assume_rec_verification_support':{
                'default': "False",
                'description': """set this to true to disable the blacklisting of servers that don't support recipient verification"""

            }, 
                           
            'always_accept':{
                'default': "False",
                'description': """Set this to always return 'DUNNO' but still perform the recipient check and fill the cache (learning mode without rejects)"""

            },              
                             
        }
        
    def lint(self):
        if not SQLALCHEMY_AVAILABLE:
            print "sqlalchemy is not installed"
            return False
        
        if not self.checkConfig():
            return False
        try:
            (poscount,negcount)=self.cache.get_total_counts()
            print "Addresscache: %s positive entries, %s negative entries"%(poscount,negcount)
        except Exception,e:
            print "DB Connection failed: %s"%str(e)
            return False
            
        return True
                           
    def __str__(self):
        return "Address Check"
  
    def examine(self,suspect):
        from_address=suspect.get_value('sender')
        if from_address==None:
            self.logger.error('No FROM address found')
            return DUNNO
      
        address=suspect.get_value('recipient')
        if address==None:
            self.logger.error('No TO address found')
            return DUNNO
        
        address=strip_address(address)
        from_address=strip_address(from_address)
        
        #check cache
        entry=self.cache.get_address(address)
        if entry!=None:
            (positive,message)=entry
            
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
        
        
        #enabled?
        test=SMTPTest(self.config)
        enabled=int(test.get_domain_config(domain, 'enabled', domainconfig))
        if not enabled:
            self.logger.info('%s: call-aheads for domain %s are disabled'%(address,domain))
            return DUNNO,None
        
        #check blacklist
        relays=test.get_relays(domain,domainconfig)
        if relays==None or len(relays)==0:
            self.logger.error("No relay for domain %s found!"%domain)
            return DUNNO,None
        
        relay=relays[0]
        self.logger.debug("Testing relay %s for domain %s"%(relay,domain))
        if self.cache.is_blacklisted(domain, relay):
            self.logger.info('%s: server %s for domain %s is blacklisted for call-aheads, skipping'%(address,relay,domain))
            return DUNNO,None
        
        #make sure we don't call-ahead ourself
        testaddress=test.maketestaddress(domain)
        if address==testaddress:
            self.logger.error("Call-ahead loop detected!")
            self.cache.blacklist(domain, relay, servercachetime, SMTPTestResult.STAGE_CONNECT, 'call-ahead loop detected')
            return DUNNO,None
        
        
        #perform call-ahead
        sender=test.get_domain_config(domain, 'sender', domainconfig, {'bounce':'','originalfrom':from_address})
        result=test.smtptest(relay,[address,testaddress],mailfrom=sender)
        
        servercachetime=test.get_domain_config(domain, 'test_server_interval', domainconfig)
        if result.state!=SMTPTestResult.TEST_OK:
            self.logger.error('Problem testing recipient verification support on server %s : %s. putting on blacklist.'%(relay,result.errormessage))
            self.cache.blacklist(domain, relay, servercachetime, result.stage, result.errormessage)
            #TODO: perform the configured fail actions
            return DUNNO,None
        
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
                neg="negative"
            self.logger.info("%s cached %s for %s seconds (%s)"%(neg,address,cachetime,msg))
            
            if positive:
                return DUNNO,None
            else:
                if self.config.getboolean(self.section,'always_accept'):
                    self.logger.info('Learning mode - accepting despite inexistent address')
                else:
                    return REJECT,msg
            
        else:
            self.logger.info('Server %s for domain %s: blacklisting for %s seconds (%s)'%(relay,domain,servercachetime,blreason))
            self.cache.blacklist(domain, relay, servercachetime, result.stage, blreason)
        return DUNNO,None
    

class SMTPTestResult(object):
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
        self.stage=SMTPTestResult.STAGE_CONNECT
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
          SMTPTestResult.ADDRESS_TEMPFAIL:'no(temp fail)',
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
    
    def maketestaddress(self,domain):
        """Return a static test address that probably doesn't exist. It is NOT randomly generated, so we can check if the incoming connection does not produce a call-ahead loop""" 
        return "rbxzg133-7tst@%s"%domain
    
    
    def get_domain_config(self,domain,key,domainconfig=None,templatedict=None):
        """Get configuration value for domain or default. Apply template string if templatedict is not None"""
        defval=self.config.get('ca_default',key)
        
        theval=defval
        if domainconfig==None: #nothing from sql
            
            #check config file overrides
            configbackend=ConfigFileBackend(self.config)
            
            #ask the config backend if we have a special server config
            backendoverride=configbackend.get_domain_config_value(domain, key)
            if backendoverride!=None:
                theval=backendoverride
        elif key in domainconfig:
            theval=domainconfig[key]
        
        if templatedict!=None:
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
                content=open(val).read()
                lines=content.split('\n')
                for line in lines:
                    fdomain,ftarget=line.split()
                    if domain.lower()==fdomain.lower():
                        return [ftarget,]
            except Exception,e:
                self.logger.error("Txt lookup failed: %s"%str(e))
        else:
            self.logger.error('unknown relay lookup type: %s'%tp)
            return None 
        
    
    def smtptest(self,relay,addrlist,helo=None,mailfrom=None,timeout=10):
        """perform a smtp check until the rcpt to stage
        returns a SMTPTestResult
        """
        result=SMTPTestResult()
        result.relay=relay
        
        if mailfrom==None:
            mailfrom=""
        

        smtp=smtplib.SMTP(local_hostname=helo)
        smtp.timeout=timeout
        #python 2.4 workaround....
        #TODO: remove when we have migrated to newer python version
        import socket
        socket.setdefaulttimeout(timeout)
        #smtp.set_debuglevel(True)
        try:
            code,msg=smtp.connect(relay, 25)
            result.banner=(code,msg)
            if code<200 or code>299:
                result.state=SMTPTestResult.TEST_FAILED
                result.errormessage="connection was not accepted: %s"%msg
                return result
        except Exception,e:
            result.errormessage=str(e)
            result.state=SMTPTestResult.TEST_FAILED
            return result
        
        
        #HELO
        result.stage=SMTPTestResult.STAGE_HELO
        try:
            code,msg=smtp.helo()
            result.heloreply=(code,msg)
            if code<200 or code>299:
                result.state=SMTPTestResult.TEST_FAILED
                result.errormessage="HELO was not accepted: %s"%msg
                return result
        except Exception,e:
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
        except Exception,e:
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
        except Exception,e:
            result.errormessage=str(e)
            result.state=SMTPTestResult.TEST_FAILED
            return result
         
        result.state=SMTPTestResult.TEST_OK
        
        try:
            smtp.quit()
        except Exception,e:
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
    
    
    def put_address(self,address,expires,positiveEntry=True,message=None):
        self.logger.error('put_address: not implemented')
    
    def get_address(self,address):
        """Returns a tuple (positive(boolean),message) if a cache entry exists, None otherwise"""
        self.logger.error('get_address: not implemented')
        return None
    
class MySQLCache(CallAheadCacheInterface):
    def __init__(self,config):
        CallAheadCacheInterface.__init__(self, config)
    
    def blacklist(self,domain,relay,seconds,failstage='rcpt_to',reason='unknown'):
        """Put a domain/relay combination on the recipient verification blacklist for a certain amount of time"""
        conn=get_session(self.config.get('AddressCheck','dbconnection'))

        statement="""INSERT INTO ca_blacklist (domain,relay,expiry_ts,check_stage,reason) VALUES (:domain,:relay,now()+interval :interval second,:checkstag,:reason)
        ON DUPLICATE KEY UPDATE expiry_ts=now()+interval :interval second,check_stage=:checkstage,reason=:reason
        """
        values={
                'domain':domain,
                'relay':relay,
                'interval':seconds,
                'checkstage':failstage,
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
        return result 
        
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
        return (poscount,negcount,blcount)
        
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
        ON DUPLICATE KEY UPDATE check_ts=now(),expiry_ts=now()+interval :interval second,positive=:positive,message=:message
        """
        #todo strip domain
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
        return (poscount,negcount)
     
    
 
    
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
        ConfigBackendInterface.__init__(self, config)
    
    def get_domain_config_value(self,domain,key):
        retval=None
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        
        res=conn.execute("SELECT confvalue FROM ca_configoverride WHERE domain=:domain and confkey=:confkey",{'domain':domain,'confkey':key})
        sc=res.scalar()
        conn.remove()
        return sc
    
    def get_domain_config_all(self,domain):
        retval=dict()
        conn=get_session(self.config.get('AddressCheck','dbconnection'))
        res=conn.execute("SELECT confkey,confvalue FROM ca_configoverride WHERE domain=:domain",{'domain':domain})
        for row in res:
            retval[row[0]]=row[1]
        conn.remove()
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
        
        self.commandlist={
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
    
    def cleanup(self,*args):
        config=get_config()
        (poscount,negcount,blcount)=MySQLCache(config).cleanup()
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
        sqlcache=MySQLCache(config)
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
                  ("wipe-address","<emailaddress>","remove <emailaddress> from the cache/history"),
                  ("wipe-domain","<domain> [positive|negative|all (default)]","remove positive/negative/all entries for domain <domain> from the cache/history"),
                  ("show-domain","<domain>","list all cache entries for domain <domain>"),
                  ("show-blacklist","","display all servers currently blacklisted for call-aheads"),
                  ("unblacklist","<relay or domain>","remove relay from the call-ahead blacklist"),
                  ("cleanup","[verbose]","clean history data from database. this can be run from cron. add 'verbose' to see how many records where cleared")      
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
        result=test.smtptest(server,addrs)
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
        cache=MySQLCache(config)
        entry=cache.get_address(address)
        if entry!=None:
            (positive,message)=entry
            tp="negative"
            if positive:
                tp="positive"
            print "We have %s cache entry for %s: %s"%(tp,address,message)
        else:
            print "No cache entry for %s"%address
        
        test=SMTPTest(config)
        relays=test.get_relays(domain,domainconfig)
        if relays==None:
                print "No relay for domain %s found!"%domain
                sys.exit(1)
        print "Relays for domain %s are %s"%(domain,relays)
        for relay in relays:
            print "Testing relay %s"%relay
            if cache.is_blacklisted(domain, relay):
                print "%s is currently blacklisted for call-aheads"%relay
            else:
                print "%s not blacklisted for call-aheads"%relay
            
            print "Checking if server supports verification...."
            
            sender=test.get_domain_config(domain, 'sender', domainconfig, {'bounce':'','originalfrom':''})
            testaddress=test.maketestaddress(domain)
            result=test.smtptest(relay,[address,testaddress],mailfrom=sender)
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
    
    def wipe_address(self,*args):
        if len(args)!=1:
            print "usage: wipe-address <address>"
            sys.exit(1)
        config=get_config()
        cache=MySQLCache(config)
        rowcount=cache.wipe_address(args[0])
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
        cache=MySQLCache(config)
        rowcount=cache.wipe_domain(domain,pos)
        print "Wiped %s %s records"%(rowcount,strpos)       
    
    def show_domain(self,*args):
        if len(args)!=1:
            print "usage: show-domain <domain>"
            sys.exit(1)
        config=get_config()
        cache=MySQLCache(config)
        domain=args[0]
        rows=cache.get_all_addresses(domain)
        
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
        cache=MySQLCache(config)
        rows=cache.get_blacklist()
        
        print "Call-ahead blacklist (domain/relay/reason):"
        for row in rows:
            domain,relay,reason,exp=row
            print "%s\t%s\t%s"%(domain,relay,reason)
            
        total=len(rows)
        print "Total %s blacklisted relays"%total
        
    def unblacklist(self,*args):
        if len(args)<1:
            print "usage: unblacklist <relay or domain>"
            sys.exit(1)
        relay=args[0]
        config=get_config()
        cache=MySQLCache(config)
        count=cache.unblacklist(relay)
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
        
        cache=MySQLCache(config)

        test=SMTPTest(config)
        relays=test.get_relays(domain,domainconfig)
        if relays==None:
            print "No relay for domain %s found!"%domain
            sys.exit(1)
        print "Relays for domain %s are %s"%(domain,relays)
        
        relay=relays[0]
        sender=test.get_domain_config(domain, 'sender', domainconfig, {'bounce':'','originalfrom':''})
        testaddress=test.maketestaddress(domain)
        result=test.smtptest(relay,[address,testaddress],mailfrom=sender)
        
        servercachetime=test.get_domain_config(domain, 'test_server_interval', domainconfig)
        if result.state!=SMTPTestResult.TEST_OK:
            print "There was a problem testing this server:"
            print result
            print "putting server on blacklist"
            cache.blacklist(domain, relay, servercachetime, result.stage, result.errormessage)
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
            
            if cache.is_blacklisted(domain, relay):
                print "Server was blacklisted - removing from blacklist"
                cache.unblacklist(relay, domain)
            
            addrstate,code,msg=result.rcptoreplies[address]
            positive=True
            cachetime=test.get_domain_config(domain, 'positive_cache_time', domainconfig)
            if addrstate==SMTPTestResult.ADDRESS_DOES_NOT_EXIST:
                positive=False
                cachetime=test.get_domain_config(domain, 'negative_cache_time', domainconfig)
            
            cache.put_address(address,cachetime,positive,msg)
            neg=""
            if not positive:
                neg="negative"
            print "%s cached %s for %s seconds"%(neg,address,cachetime)
        else:
            print "Server accepts any recipient"
            if config.getboolean('AddressCheck','always_assume_rec_verification_support'):
                print "blacklistings disabled in config- not blacklisting"
            else:
                cache.blacklist(domain, relay, servercachetime, result.stage, 'accepts any recipient')
                print "Server blacklisted"
            
        
if __name__=='__main__':
    logging.basicConfig()  
    cli=SMTPTestCommandLineInterface()
    cli.performcommand()