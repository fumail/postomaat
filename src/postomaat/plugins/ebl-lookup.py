# -*- coding: UTF-8 -*-

from postomaat.shared import ScannerPlugin, DEFER_IF_PERMIT, DUNNO, REJECT, strip_address, extract_domain, apply_template, FileList
from postomaat.extensions.dnsquery import DNSQUERY_EXTENSION_ENABLED, lookup
import re
from hashlib import sha1, md5
try:
    import SRS
    HAVE_SRS=True
    class SRSDecode(SRS.Shortcut.Shortcut):
        def parse(self, user, srshost=None):
            user, m = self.srs0re.subn('', user, 1)
            assert m, "Reverse address does not match %s." % self.srs0re.pattern
            hash, timestamp, sendhost, senduser = user.split(SRS.SRSSEP, 3)[-4:]
            if not sendhost and srshost:
                sendhost = srshost
            return sendhost, senduser
except ImportError:
    SRS=None
    HAVE_SRS=False
    SRSDecode = None



class EBLLookup(ScannerPlugin):
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.whitelist = None
        
        self.requiredvars={
            'whitelist_file':{
                'default':'/etc/postomaat/conf.d/ebl-whitelist.txt',
                'description':'path to file containing whitelisted sender domains',
            },
            'dnszone':{
                'default':'ebl.msbl.org',
                'description':'the DNS zone to query. defaults to ebl.msbl.org',
            },
            'hash': {
                'default':'sha1',
                'description':'hash function used by DNS zone. Use one of sha1, md5'
            },
            'response':{
                'default':'127.0.0.2',
                'description':'expected response of zone query',
            },
            'messagetemplate':{
                'default':'${sender} listed by ${dnszone} for ${message}'
            },
            'normalisation':{
                'default':'ebl',
                'description':'type of normalisation to be applied to email addresses before hashing. choose one of ebl (full normalisation according to ebl.msbl.org standard), low (lowercase only)'
            },
            'decode_srs':{
                'default':'0',
                'description':'decode SRS encoded sender addresses before lookup'
            },
            'check_srs_only':{
                'default':'0',
                'description':'only check decoded SRS sender addresses against the blacklist zone'
            },
        }


    
    def _is_whitelisted(self, from_domain):
        whitelist_file = self.config.get(self.section,'whitelist_file','').strip()
        if whitelist_file == '':
            return False
        
        whitelisted = False
        self.whitelist = FileList(whitelist_file,lowercase=True)
        if from_domain in self.whitelist.get_list():
            whitelisted = True
            
        return whitelisted
        
        
        
    def _email_normalise_ebl(self, address):
        if not '@' in address:
            self.logger.error('Not an email address: %s' % address)
            return address
        
        address = address.lower()
        
        lhs, domain = address.split('@',1)
        domainparts = domain.split('.')
        
        if 'googlemail' in domainparts: # replace googlemail with gmail
            tld = '.'.join(domainparts[1:])
            domain = 'gmail.%s' % tld
            domainparts = ['gmail', tld]
        
        if '+' in lhs: # strip all + tags
            lhs = lhs.split('+')[0]
            
        if 'gmail' in domainparts: # discard periods in gmail
            lhs = lhs.replace('.', '')
            
        if 'yahoo' in domainparts or 'ymail' in domainparts: # strip - tags from yahoo
            lhs = lhs.split('-')[0]
            
        lhs = re.sub('^(envelope-from|id|r|receiver)=', '', lhs) # strip mail log prefixes
            
        return '%s@%s' % (lhs, domain)
    
    
    
    def _email_normalise_low(self, address):
        address = address.lower()
        return address
    
    
    
    def _email_normalise(self, address):
        n = self.config.get(self.section,'normalisation')
        if n == 'ebl':
            address = self._email_normalise_ebl(address)
        elif n == 'low':
            address = self._email_normalise_low(address)
        return address
    
    
    
    def _create_hash(self, value):
        hashtype = self.config.get(self.section,'hash').lower()
        if hashtype == 'sha1':
            myhash = sha1(value).hexdigest()
        elif hashtype == 'md5':
            myhash = md5(value).hexdigest()
        else:
            myhash = ''
        return myhash
    
    
    
    def _ebl_lookup(self, addr_hash):
        listed = False
        message = None
        
        dnszone = self.config.get(self.section,'dnszone','').strip()
        response = self.config.get(self.section,'response','').strip()
        query = '%s.%s' % (addr_hash, dnszone)
        result = lookup(query)
        if result is not None:
            for rec in result:
                if rec == response:
                    listed = True
                    result = lookup(query, qtype='TXT')
                    if result:
                        message = result[0]
                    break
                
        return listed, message
    
    
    
    def _is_srs(self, addr):
        if addr.startswith('SRS0=') or addr.startswith('SRS1='):
            return True
        return False
    
    
    
    def _decode_srs(self, addr):
        srs = SRSDecode()
        return srs.reverse(addr)
    
    
    
    def examine(self, suspect):
        if not DNSQUERY_EXTENSION_ENABLED:
            return DUNNO
        
        from_address=suspect.get_value('sender')
        if from_address is None:
            self.logger.warning('No FROM address found')
            return DEFER_IF_PERMIT,'internal policy error (no from address)'
        
        from_address=strip_address(from_address)
        if self.config.getboolean(self.section,'check_srs_only') and not self._is_srs(from_address):
            self.logger.info('skipping non SRS address %s' % from_address)
            return DUNNO
        
        if HAVE_SRS and self.config.getboolean(self.section,'decode_srs'):
            from_address = self._decode_srs(from_address)

        from_domain=extract_domain(from_address)
        if self._is_whitelisted(from_domain):
            return DUNNO
        
        from_address = self._email_normalise(from_address)
        addr_hash = self._create_hash(from_address)
        listed, message = self._ebl_lookup(addr_hash)
        
        if listed:
            values = {
                'dnszone': self.config.get(self.section,'dnszone','').strip(),
                'message': message,
            }
            message = apply_template(self.config.get(self.section,'messagetemplate'),suspect, values)
            return REJECT, message
        else:
            return DUNNO
        
        
    
    def lint(self):
        dnszone = self.config.get(self.section,'dnszone','').strip()
        print('querying zone %s' % dnszone)
        
        lint_ok = True
        if not self.checkConfig():
            print('Error checking config')
            lint_ok = False
            
        if not DNSQUERY_EXTENSION_ENABLED:
            print("no DNS resolver library available - this plugin will do nothing")
            lint_ok = False
            
        if self.config.getboolean(self.section,'decode_srs') and not HAVE_SRS:
            print('decode_srs enabled but SRS library is not available')
            lint_ok = False
            
        hashtype = self.config.get(self.section,'hash').lower()
        if hashtype not in ['sha1', 'md5']:
            lint_ok = False
            print('unsupported hash type %s' % hashtype)
            
        normalisation = self.config.get(self.section,'normalisation')
        if normalisation not in ['ebl', 'low']:
            lint_ok = False
            print('unsupported normalsation type %s' % normalisation)
        
        addr_hash = self._create_hash('noemail@example.com')
        listed, message = self._ebl_lookup(addr_hash)
        if not listed:
            lint_ok = False
            print('test entry not found in dns zone')
        else:
            print('test entry found in dns zone: %s' % message)
            
        if lint_ok:
            whitelist_file = self.config.get(self.section,'whitelist_file')
            if whitelist_file.strip() == '':
                print('No whitelist defined')
                
        return lint_ok
                
        
    
    
    
    
        