#!/usr/bin/python
# -*- coding: utf-8 -*-

#TODO: do we need a "does not match regex" operator? (can curently be written as !bla=~/blubb/
#TODO: regex modifiers

#IDEA: pseudo field "senderdomain"
#IDEA: operator "blacklistlookup"

from postomaat.shared import ScannerPlugin,DUNNO,REJECT,DEFER,DEFER_IF_REJECT,DEFER_IF_PERMIT,OK,DISCARD,FILTER,HOLD,PREPEND,REDIRECT,WARN

from pyparsing import Optional
PYPARSING_AVAILABLE=False
try:
    from pyparsing import infixNotation, opAssoc, Keyword, Word, alphas,oneOf,nums,alphas,Literal,restOfLine,ParseException,QuotedString
    PYPARSING_AVAILABLE=True
except ImportError:
    pass

import logging
import re
import os
import time
import string

#allowed keywords at start of line
postfixfields = ["smtpd_access_policy" , "protocol_state" , "protocol_name" , "helo_name",  "queue_id" , "sender" ,  "recipient" , "recipient_count" , "client_address" , "client_name" , "reverse_client_name" , "instance"  , "sasl_method" , "sasl_username" , "sasl_sender" , "size" , "ccert_subject" , "ccert_fingerprint" , "encryption_protocol" , "encryption_cipher" , "encryption_keysize" , "etrn_domain" , "stress" , "ccert_pubkey_fingerprint"]

#what keywords return a integer value
numeric=['size','encryption_keysize','recipient_count']

if PYPARSING_AVAILABLE:
    #allowed operators
    AttOperator=oneOf("== != ~= > <")
    
    #allowed actions
    ACTION = oneOf(map(string.upper, [DUNNO,REJECT,DEFER,DEFER_IF_REJECT,DEFER_IF_PERMIT,OK,DISCARD,FILTER,HOLD,PREPEND,REDIRECT,WARN]))

class ValueChecker(object):

    def __init__(self,values,pfixname,op,checkval,modifiers=None):
        self.debug=True
        self.pfixname=pfixname
        self.op=op
        self.checkval=checkval
        self.label="%s %s %s"%(pfixname,op,checkval)
        self.values=values #all values
        self.value=self.get_value() # the requested value
        self.logger=logging.getLogger('postomaat.complexrules.valuecheck')
        self.modifiers=modifiers
        self.funcs={
         '==':self.fn_equals,
         '!=':self.fn_notequals, 
         '~=':self.fn_regexmatches,
         '<':self.fn_lt,
         '>':self.fn_gt,   
        }
        
    def get_value(self,name=None,defval=None):
        if name==None:
            name=self.pfixname
            
        if name not in self.values:
            return defval
        return self.values[name]
    
    def fn_equals(self):
        return self.value==self.checkval

    def fn_notequals(self):
        return self.value!=self.checkval
    
    def fn_gt(self):
        if self.pfixname not in numeric:
            self.logger.warn("can not use use < and > comparison operator on non-numeric value %s"%self.pfixname)
            return False
        if self.value==None:
            return False
        numval=int(self.value)
        return numval>self.checkval
    
    def fn_lt(self):
        if self.pfixname not in numeric:
            self.logger.warn("can not use use < and > comparison operator on non-numeric value %s"%self.pfixname)
            return False
        if self.value==None:
            return False
        numval=int(self.value)
        return numval<self.checkval
    
    def fn_regexmatches(self):
        v=str(self.value)
        reflags=0
        if self.modifiers!=None:
            for flag in self.modifiers:
                flag=flag.lower()
                if flag=='i':
                    reflags|=re.I
                elif flag=='m':
                    reflags|=re.M
                else:
                    self.logger.warn("unknown/unsupported regex flag '%s' - ignoring this flag"%(flag))
        
        try:
            match= re.search(self.checkval, v,reflags)
        except Exception,e:
            logging.error(e)
        return match!=None
    
    def __bool__(self):
        func= self.funcs[self.op]
        res=func()
        #logmsg="%s %s %s ? : %s (%.4f)"%(self.pfixname,self.op,self.checkval,res,runtime)
        #self.logger.debug(logmsg)
        return res
        
    
    def __str__(self):
        return self.label
    __repr__ = __str__
    __nonzero__ = __bool__


class BoolBinOp(object):
    def __init__(self,t):
        self.args = t[0][0::2]
    def __str__(self):
        sep = " %s " % self.reprsymbol
        return "(" + sep.join(map(str,self.args)) + ")"
    def __bool__(self):
        return self.evalop(bool(a) for a in self.args)
    __nonzero__ = __bool__
    __repr__ = __str__

class BoolAnd(BoolBinOp):
    reprsymbol = '&&'
    evalop = all

class BoolOr(BoolBinOp):
    reprsymbol = ',,'
    evalop = any

class BoolNot(object):
    def __init__(self,t):
        self.arg = t[0][1]
    def __bool__(self):
        v = bool(self.arg)
        return not v
    def __str__(self):
        return "!" + str(self.arg)
    __repr__ = __str__
    __nonzero__ = __bool__


if PYPARSING_AVAILABLE:
    PF_KEYWORD=oneOf(postfixfields)
    intnum = Word(nums).setParseAction( lambda s,l,t: [ int(t[0]) ] )
    charstring=QuotedString(quoteChar='"') | QuotedString(quoteChar="'") | (QuotedString(quoteChar='/') + Optional(Word("im")))
    AttOperand= charstring | intnum


def makeparser(values):
    SimpleExpression = PF_KEYWORD('pfvalue') + AttOperator('operator') + AttOperand('testvalue')
        
    booleanrule = infixNotation( SimpleExpression,
        [
        ("!", 1, opAssoc.RIGHT, BoolNot),
        ("&&", 2, opAssoc.LEFT,  BoolAnd),
        ("||",  2, opAssoc.LEFT,  BoolOr),
        ])
    
    def evalResult(loc,pos,tokens):
        modifiers=None
        
        l=len(tokens)
        if l==3:
            pfixname,op,checkval=tokens
        elif l==4:
            pfixname,op,checkval,modifiers=tokens
        else:
            logging.error("Parser error, got unexpected token amount, tokens=%s"%tokens)
        #print "checking %s %s %s"%(pfixname,op,checkval)
        
        return ValueChecker(values,pfixname,op,checkval,modifiers)

    SimpleExpression.setParseAction(evalResult)
    #SimpleExpression.setDebug()
    configline=booleanrule + ACTION + restOfLine
    return configline


class ComplexRuleParser(object):
    def __init__(self):
        self.rules=[]
        self.logger=logging.getLogger('postomaat.complexruleparser')
        
        self.warn_rule_execution_time=0.5 #warn limit per rule
        self.warn_total_execution_time=3 #warn limit for all rules
        self.max_execution_time=5.0  #hard limit
    
    def add_rule(self,rule):
        try:
            _=makeparser({}).parseString(rule)  #test
            self.rules.append(rule)
            return True
        except ParseException,pe:
            self.logger.error("Could not parse rule -->%s<-- "%rule)
            self.logger.error(str(pe))
        return False
    
    def clear_rules(self):
        self.rules=[]
        
    def rules_from_string(self,all_rules):
        if all_rules==None:
            return
        all_ok=True
        for line in all_rules.splitlines():
            line=line.strip()
            if line=='' or line.startswith('#'):
                continue
            if not self.add_rule(line):
                all_ok=False
                
        return all_ok

    def apply(self,values):
        totalstart=time.time()
        parser=makeparser(values)
        ruletimes={}
        for rule in self.rules:
            rulestart=time.time()
            try:
                parsetree=parser.parseString(rule)  #test
                checkrule,action,message=parsetree
                bmatch=bool(checkrule)
                
                now=time.time()
                ruletime=now-rulestart
                ruletimes[ruletime]=rule
                
                if self.warn_rule_execution_time>0 and ruletime>self.warn_rule_execution_time:
                    self.logger.warn("warning: slow complexrule execution: %.4f for %s"%(ruletime,rule))
                
                if bmatch:
                    logmsg="postomaat-rulehit: sender=%s recipient=%s rule=%s %s %s"%(values.get('sender'),values.get('recipient'),checkrule,action,message)
                    self.logger.info(logmsg)
                    return action,message.strip()
                
                if now-time.time()>self.max_execution_time:
                    self.logger.warn("warning: complex max execution time limit reached - not all rules have been executed")
                    break
                
            except ParseException,pe:
                self.logger.warning("""Could not apply rule "%s" to message %s """%(rule,values))
                self.logger.warning(str(pe))
                
        totaltime=time.time()-totalstart
        if self.warn_total_execution_time>0 and totaltime>self.warn_total_execution_time:
            self.logger.warn("warning: complexrules are getting slow: total rule exec time: %.4f"%totaltime)
        return DUNNO,''



class FileReloader(object):
    def __init__(self,filename):
        self.filename=filename
        self.content=[]
        
        self.reloadinterval=30
        self.lastreload=0
        self.logger=logging.getLogger('postomaat.complexfilereloader')
        self.content=None
        if filename!=None:
            self.reloadifnecessary()
        
        
    def reloadifnecessary(self):
        now=time.time()
        #check if reloadinterval has passed
        if now-self.lastreload<self.reloadinterval:
            return False
        if self.filechanged():
            self._reload()
            return True
        return False
    
    def filechanged(self):
        if self.filename==None:
            return False
        statinfo=os.stat(self.filename)
        ctime=statinfo.st_ctime
        if ctime>self.lastreload:
            return True
        return False  

    def _reload(self):
        self.logger.info('Reloading rule file %s'%self.filename)
        statinfo=os.stat(self.filename)
        ctime=statinfo.st_ctime
        self.lastreload=ctime
        fp=open(self.filename,'r')
        content=fp.read()
        self.content=content


class ComplexRules(ScannerPlugin):
    """ """
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.requiredvars={
            'filename':{
                'default':'/etc/postomaat/complexrules.cf',
                'description':'File containing rules',
            },
        }
        self.ruleparser=ComplexRuleParser()
        self.filereloader=FileReloader(None)
        
    def examine(self,suspect):        
        if not PYPARSING_AVAILABLE:
            return DUNNO,''
        
        filename=self.config.get(self.section,'filename').strip()
        if not os.path.exists(filename):
            self.logger.error("Rulefile %s does not exist"%filename)
            return DUNNO,''
        self.filereloader.filename=filename
        newcontent=self.filereloader.reloadifnecessary()
        if newcontent:
            self.ruleparser.clear_rules()
            reloadok=self.ruleparser.rules_from_string(self.filereloader.content)
            numrules=len(self.ruleparser.rules)
            if reloadok:
                okmsg="all rules ok"
            else:
                okmsg="some rules failed to load"
            self.logger.info("Rule reload complete, %s rules now active, (%s)"%(numrules,okmsg))
        
        retaction,retmessage=self.ruleparser.apply(suspect.values)
        return retaction,retmessage

    def lint(self):
        if not PYPARSING_AVAILABLE:
            print "pyparsing is not installed, can not use complex rules"
            return False
        
        
        
        if not self.checkConfig():
            print 'Error checking config'
            return False

        filename=self.config.get(self.section,'filename').strip()
        if not os.path.exists(filename):
            print "Rulefile %s does not exist"%filename
            return False
        
        self.filereloader.filename=filename
        newcontent=self.filereloader.reloadifnecessary()
        assert newcontent
        
        self.ruleparser.clear_rules()
        ok= self.ruleparser.rules_from_string(self.filereloader.content)
        rulecount=len(self.ruleparser.rules)
        print "%s rules ok"%(rulecount)
        return ok

                        
    def __str__(self):
        return "Complex Rules"

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)
    c=ComplexRuleParser()
    print "Load Rules:\n----"
    rules="""
reverse_client_name == "unknown" && helo_name=="21cn.com" REJECT go away! 
reverse_client_name == "unknown" && helo_name~=/^\[[0-9a-fA-F:.]+\]$/im REJECT No FcrDNS and address literal HELO - Who are you?

sender~=/^EX_.+@girlfriends.com/i && (size<100 || size>20000) REJECT say something.. but not everything
"""
    print rules
    
    c.rules_from_string(rules)
    print "----"
    print "%s rules loaded"%(len(c.rules))
    print "Tests:"
    message1={'reverse_client_name':'unknown','helo_name':'21cn.com'}
    message2={'reverse_client_name':'unknown','helo_name':'gmail.com','size':'5000'}
    message3={'reverse_client_name':'bla.com','helo_name':'21cn.com'}
    addr_literal={'reverse_client_name':'unknown','helo_name':'[1.3.3.7]'}
    small_message={'size':'5','sender':'ex_8@girlfriends.com'}
    large_message={'size':'100000','sender':'ex_8@girlfriends.com'}
    medium_message={'size':'300','sender':'ex_8@girlfriends.com'}
    tests=[
     (message1,'REJECT','go away!'),  
     (message2,'DUNNO',''),      
     (message3,'DUNNO',''), 
     (addr_literal,'REJECT','No FcrDNS and address literal HELO - Who are you?'),
     (small_message,'REJECT','say something.. but not everything'),
     (large_message,'REJECT','say something.. but not everything'),
     (medium_message,'DUNNO',''),
    ]
    
    for test in tests:
        msg,expaction,expmessage=test
        print ""
        print "Testing message: %s..."%msg
        retaction,retmessage=c.apply(msg)
        retaction=retaction.upper()
        if retaction==expaction and retmessage==expmessage:
            print "Test OK (%s %s)"%(retaction,retmessage)
        else:
            print "FAIL! : Expected '%s %s' got '%s %s'"%(expaction,expmessage,retaction,retmessage)
    
   
    
    
    
        
    
    