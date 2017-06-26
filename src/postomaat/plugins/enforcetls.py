# -*- coding: UTF-8 -*-

from postomaat.shared import ScannerPlugin, DUNNO, strip_address, extract_domain, apply_template, FileList, \
    string_to_actioncode, SettingsCache
from postomaat.db import SQLALCHEMY_AVAILABLE,get_session
import os



SETTINGSCACHE=None



class EnforceTLS(ScannerPlugin):
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.selective_domain_loader = None
        
        self.requiredvars={
            'domainlist':{
                'default':'',
                'description':"""
                if this is empty, all recipient domains will be forced to use TLS
                txt:<filename> - get from simple textfile which lists one domain per line
                sql:<statement> - get from sql database :domain will be replaced with the actual domain name. must return field enforce_inbound_tls
                """,
            },
            'dbconnection':{
                'default':"mysql://root@localhost/enforcetls?charset=utf8",
                'description':'SQLAlchemy Connection string',
            },
            'action':{
                'default':'DEFER',
                'description':'Action if connection is not TLS encrypted. set to DUNNO, DEFER, REJECT',
            },
            'messagetemplate':{
                'default':'Unencrypted connection. This recipient requires TLS'
            }
        }



    def get_sql_settings(self, to_domain, dbconnection, sqlquery):
        global SETTINGSCACHE

        if SETTINGSCACHE is None:
            SETTINGSCACHE = SettingsCache()

        cached = SETTINGSCACHE.get_cache(to_domain)
        if cached is not None:
            self.logger.debug("got cached settings for %s" % to_domain)
            return cached

        settings = {'enforce_inbound_tls': False}

        try:
            session = get_session(dbconnection)

            # get domain settings
            dom = session.execute(sqlquery, {'domain': to_domain}).fetchall()

            if not dom and not dom[0]:
                self.logger.warning(
                    "Can not load domain settings - domain %s not found. Using default settings." % to_domain)
            else:
                settings['enforce_inbound_tls'] = dom[0][0]

            session.close()

        except Exception as e:
            self.logger.error("Exception while loading settings for %s : %s" % (to_domain, str(e)))

        SETTINGSCACHE.put_cache(to_domain, settings)
        self.logger.debug("refreshed settings for %s" % to_domain)
        return settings



    def enforce_domain(self, to_domain):
        enforce = False

        domainlist = self.config.get(self.section,'domainlist')
        if domainlist.strip() == '':
            enforce = True

        elif domainlist.startswith('txt:'):
            domainfile = domainlist[4:]
            if self.selective_domain_loader is None:
                self.selective_domain_loader=FileList(domainfile,lowercase=True)
                if to_domain in self.selective_domain_loader.get_list():
                    enforce = True

        elif domainlist.startswith('sql:'):
            sqlquery = domainlist[4:]
            dbconnection = self.config.get(self.section,'dbconnection')
            setting = self.get_sql_settings(to_domain, dbconnection, sqlquery)
            if setting.get('enforce_inbound_tls'):
                enforce = True

        return enforce

    
    
    def examine(self, suspect):
        encryption_protocol = suspect.get_value('encryption_protocol')
        recipient=suspect.get_value('recipient')
        
        rcpt_email = strip_address(recipient)
        if rcpt_email=='' or rcpt_email is None:
            return DUNNO

        enforce = self.enforce_domain(extract_domain(rcpt_email))

        action = DUNNO
        message = None
        if enforce and encryption_protocol == '':
            action=string_to_actioncode(self.config.get(self.section, 'action'))
            message = apply_template(self.config.get(self.section,'messagetemplate'),suspect)
            
        return action, message
    
    
    
    def lint(self):
        lint_ok = True
        if not self.checkConfig():
            print 'Error checking config'
            lint_ok = False
            
        if lint_ok:
            domainlist = self.config.get(self.section,'domainlist')
            if domainlist.strip() == '':
                print 'Enforcing TLS for all domains'
            elif domainlist.startswith('txt:'):
                domainfile = domainlist[4:]
                if not os.path.exists(domainfile):
                    print 'Cannot find domain file %s' % domainfile
                    lint_ok = False
            elif domainlist.startswith('sql:'):
                sqlquery = domainlist[4:]
                if not sqlquery.lower().startswith('select '):
                    lint_ok = False
                    print 'SQL statement must be a SELECT query'
                if not SQLALCHEMY_AVAILABLE:
                    print 'SQLAlchemy not available, cannot use sql backend'
                if lint_ok:
                    dbconnection = self.config.get(self.section, 'dbconnection')
                    try:
                        conn=get_session(dbconnection)
                        conn.execute(sqlquery, {'domain':'example.com'})
                    except Exception as e:
                        lint_ok = False
                        print str(e)
            else:
                lint_ok = False
                print 'Could not determine domain list backend type'
        
        return lint_ok
    
    
    
    def __str__(self):
        return "EnforceTLS"