import optparse
import sys
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import os


def checkLogfileConfig(configfile):
    """ Checks Logfile configuration in file as used by logging.config.fileConfig
    Using the fileConfig options produces error messages which can not be seen if
    a service is started. However in test mode the loggers are not active.

    configfile   name and path of logging configuration file
    return       true for no error
    """
    if not os.path.exists(configfile):
        print("Config file not found!")
        print("Filename: "+str(configfile))
        print("")
        parser.print_help()
        return False

    logconfig=ConfigParser.ConfigParser()
    logconfig.readfp(open(configfile))

    # get list of sections
    sectionList = logconfig.sections()

    if logconfig.has_section("handler_logfile"):
        if logconfig.has_option('handler_logfile', 'class'):
            logfileClass=logconfig.get('handler_logfile','class')
            if logfileClass=="handlers.TimedRotatingFileHandler":
                if logconfig.has_option('handler_logfile', 'args'):
                    logfileArgs=logconfig.get('handler_logfile','args')
                    logfileArgs= logfileArgs.replace("(","").replace(")","")
                    logfileArgs= logfileArgs.replace("'","").replace('"',"")
                    logfileArgsList = logfileArgs.split(",")
                    if (len(logfileArgsList) > 0 ):
                        firstArg = logfileArgsList[0]
                    else:
                        firstArg = logfileArgs

                    if firstArg.strip():
                       try:
                           firstArgDir = os.path.dirname(firstArg)
                           if not os.path.isdir(firstArgDir):
                               print("ERROR: Logfile handler output path as defined in ")
                               print("       the config file does not exist. Please create")
                               print("       the target directory containing the log file manually")
                               print("       or change the configuration.")
                               print("")
                               print("       Config file    : \""+str(configfile)+"\"")
                               print("       Log file given : \""+str(firstArg)+"\"")
                               print("       Log file dir extracted and tested: \""+str(firstArgDir)+"\"")
                               return False
                       except:
                           # pass since it is possible to define a function
                           # handling the output filename
                           print("Could extracting directory from "+str(firstArg))
                           pass
                else:
                    print("INFO: Logfile handler has no key 'args' which is used")
                    print("      to define a log filename. Skipping test for the")
                    print("      existence of the logfile directory...")
            else:
                print("INFO: Logfile has section 'handler_logfile' but ")
                print("      class differs from haindlers.TimedRotatingFileHandler.")
                print("      Skipping directory existence test fore logfile handler...")
        else:
            print("INFO: Logfile has section 'handler_logfile' but no")
            print("      class keyword defined.")
            print("      Skipping directory existence test fore logfile handler...")

    # no error
    return True

#--------#
#- test -#
#--------#
if __name__ == "__main__":
    parser = optparse.OptionParser()

    parser.add_option("-c", "--config", action="store", dest="configfile", default=None,
                      help="configuration file")

    (opts, args) = parser.parse_args()

    if len(args) > 0:
        print("Unknown option(s): %s" % args)
        print("")
        parser.print_help()
        sys.exit(1)

    if not opts.configfile:
        print("Config file missing as an argument!")
        print("")
        parser.print_help()
        sys.exit(1)

    configfile = opts.configfile

    if not checkLogfileConfig(configfile):
        sys.exit(1)
