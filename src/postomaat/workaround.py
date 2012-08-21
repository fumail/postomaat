
#work around bug http://bugs.python.org/issue14452
#http://serverfault.com/questions/407643/rsyslog-update-on-amazon-linux-suddenly-treats-info-level-messages-as-emerg
import logging
class BOMLessFormatter(logging.Formatter):
    def format(self, record):
        return logging.Formatter.format(self, record).encode('utf-8')
