# -*- coding: UTF-8 -*-

__version__ = "0.0.1"

from postomaat.shared import ScannerPlugin, OK, DUNNO, REJECT, DISCARD, DEFER_IF_PERMIT, strip_address, extract_domain, get_default_cache
from postomaat.extensions.sql import SQL_EXTENSION_ENABLED, get_session
import fnmatch


GLOBALSCOPE = '$GLOBAL'
LISTING_TYPES = (dict(name='whitelist_to', cmp=['to_address']), 
                 dict(name='more_spam_to', cmp=['to_address']), 
                 dict(name='all_spam_to', cmp=['to_address']),
                 dict(name='whitelist_from', cmp=['from_address', 'from_domain']),
                 dict(name='blacklist_to', cmp=['to_address']),
                 dict(name='blacklist_from', cmp=['from_address', 'from_domain']),
                 )



if SQL_EXTENSION_ENABLED:
    from sqlalchemy import Column
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.types import Unicode, Integer
    
    DeclarativeBase = declarative_base()
    metadata = DeclarativeBase.metadata
    
    class UserPref(DeclarativeBase):
        __tablename__ = 'userpref'
        prefid = Column(Integer, primary_key=True)
        username = Column(Unicode(100),nullable=False)
        preference = Column(Unicode(30),nullable=False)
        value = Column(Unicode(100),nullable=False)
    



class BlackWhiteList(ScannerPlugin):
    """
    This is a black- and whitelisting plugin 
    reading the spamassassin userpref table from an SQL database. 
    """
                                         
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.requiredvars={
            'dbconnection':{
                'default':"mysql://spamassassin@localhost/spamassassin?charset=utf8",
                'description':'SQLAlchemy connection string',
            },
            'usecache':{
                'default':"True",
                'description':'Use Mem Cache. This is recommended. However, if enabled it will take up to 5 minutes until a listing gets effective.',
            },
            'action_whitelist_to':{
                'default':"OK",
                'description':'Action for this listing type',
            },
            'message_whitelist_to':{
                'default':"",
                'description':'Message for this listing type',
            },
            'action_more_spam_to':{
                'default':"OK",
                'description':'Action for this listing type',
            },
            'message_more_spam_to':{
                'default':"",
                'description':'Message for this listing type',
            },
            'action_all_spam_to':{
                'default':"OK",
                'description':'Action for this listing type',
            },
            'message_all_spam_to':{
                'default':"",
                'description':'Message for this listing type',
            },
            'action_whitelist_from':{
                'default':"OK",
                'description':'Action for this listing type',
            },
            'message_whitelist_from':{
                'default':"",
                'description':'Message for this listing type',
            },
            'action_blacklist_to':{
                'default':"REJECT",
                'description':'Action for this listing type',
            },
            'message_blacklist_to':{
                'default':"",
                'description':'Blacklisted recipient',
            },
            'action_blacklist_from':{
                'default':"REJECT",
                'description':'Action for this listing type',
            },
            'message_blacklist_from':{
                'default':"",
                'description':'Blacklisted sender',
            },           
        }
        
        
        
    def _get_listings(self):
        usecache = self.config.getboolean(self.section,'usecache')
        listings = None
        cache = get_default_cache()
        if usecache:
            listings = cache.get('listings')
        if not listings:
            listings = {}
            try:
                session = get_session(self.config.get(self.section,'dbconnection'))
                listing_types = [(l['name']).decode('utf-8') for l in LISTING_TYPES]
                result = session.query(UserPref).filter(UserPref.preference.in_(listing_types)).all()
                
                for r in result:
                    listing_type = r.preference
                    if not listing_type in listings:
                        listings[listing_type] = {}
                    username = r.username
                    if username.startswith('*@'): # roundcube sauserprefs plugin domain wide scope
                        username = username.lstrip('*@')
                    if not username in listings[listing_type]:
                        listings[listing_type][username] = []
                    listings[listing_type][username].append(r.value)
                    
            except Exception as e:
                self.logger.error('Failed to get listings: %s' % str(e))
            if listings and usecache:
                cache.put('listings', listings)
        return listings
    
    
    
    def _check_list(self, listtype, listings, user, value):
        if not listings:
            return False
        if not listtype in listings:
            return False
        
        listed = False
        userlistings = listings[listtype].get(user, [])
        for l in userlistings:
            if fnmatch.fnmatch(value, l):
                listed = True
                break
        return listed
    
    
    
    def _get_action(self, checkname):
        actionstring = self.config.get(self.section,'action_%s' % checkname).upper()
        if actionstring == 'OK':
            action = OK
        elif actionstring == 'DUNNO':
            action = DUNNO
        elif actionstring == 'REJECT':
            action = REJECT
        elif actionstring == 'DISCARD':
            action = DISCARD
        else:
            action = None
            self.logger.warning('Invalid action: %s in option action_%s' % (actionstring, checkname))
        return action
    
        
        
    def _get_message(self, checkname):
        message = self.config.get(self.section,'message_%s' % checkname).strip()
        if not message:
            message = None
        return message
    
        
        
    def examine(self,suspect):
        if not SQL_EXTENSION_ENABLED:
            return DUNNO
        
        from_address=suspect.get_value('sender')
        if from_address is None:
            self.logger.warning('No FROM address found')
            return DEFER_IF_PERMIT,'internal policy error (no from address)'
        
        from_address=strip_address(from_address)
        try:
            from_domain = extract_domain(from_address)
        except ValueError as e:
            self.logger.warning(str(e))
            return DUNNO
        
        to_address=suspect.get_value('recipient')
        if to_address is None:
            self.logger.warning('No RCPT address found')
            return DEFER_IF_PERMIT,'internal policy error (no rcpt address)'
        
        to_address=strip_address(to_address)
        to_domain=extract_domain(to_address)
                  
        listings = self._get_listings()
        result = DUNNO
        message = None

        compare = ''
        found = False
        for check in LISTING_TYPES:
            for cmp_value in check['cmp']:
                if cmp_value == 'to_address':
                    compare = to_address
                elif cmp_value == 'from_address':
                    compare = from_address
                elif cmp_value == 'from_domain':
                    compare = from_domain

                if compare is None:
                    compare = ''
                
                for scope in [GLOBALSCOPE, '%%%s' % to_domain, to_address]:
                    if self._check_list(check['name'], listings, scope, compare):
                        result = self._get_action(check['name'])
                        message = self._get_message(check['name'])
                        found = True
                        break
                if found:
                    break
            if found:
                break
        
        return result, message
        
        
        
    def lint(self):
        status = True
        if not SQL_EXTENSION_ENABLED:
            print("sqlalchemy is not installed")
            status = False
            
        try:
            session = get_session(self.config.get(self.section,'dbconnection'))
            try:
                session.query(UserPref).first()
            except Exception as e:
                print("Table or field configuration error: %s"%str(e))
                status = False
        except Exception as e:
            print("DB Connection failed. Reason: %s"%(str(e)))
            status = False
            
        if status:
            listings = self._get_listings()
            count = 0
            for listingtype in listings:
                for user in listings[listingtype]:
                    count += len(listings[listingtype][user])
            print("found %s listings" % count)
            
        for check in LISTING_TYPES:
            if self._get_action(check['name']) is None:
                print('Invalid action %s for action_%s' % (self.config.get(self.section,'action_%s' % check['name']), check['name']))
                status = False
            
        return status
    
    
    def __str__(self):
        return "BlackWhiteList"
    
    
    
    