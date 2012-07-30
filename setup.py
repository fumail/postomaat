from distutils.core import setup
import glob
import sys
sys.path.insert(0,'src')
import os

#store old content of version file here
#if we have git available, temporarily overwrite the file
#so we can report the git commit id in fuglu --version 
OLD_VERSFILE_CONTENT=None
VERSFILE='src/postomaat/__init__.py'

def git_version():
    from postomaat import POSTOMAAT_VERSION
    global VERSFILE,OLD_VERSFILE_CONTENT
    try:
        import subprocess
        x=subprocess.Popen(['git','describe'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        ret=x.wait()
        if ret==0:
            stdout,stderr=x.communicate()
            vers=stdout.strip()
            if os.path.isfile(VERSFILE):
                OLD_VERSFILE_CONTENT=open(VERSFILE,'r').read()
                buff=OLD_VERSFILE_CONTENT.replace(POSTOMAAT_VERSION,vers)
                open(VERSFILE,'w').write(buff)
            return vers
        else:
            return POSTOMAAT_VERSION
    except Exception,e:
        return POSTOMAAT_VERSION



setup(name = "postomaat",
    version = git_version(),
    description = "Postomaat Policy Daemon",
    author = "O. Schacher",
    url='http://www.wgwh.ch',
    author_email = "oli@wgwh.ch",
    package_dir={'':'src'},
    packages = ['postomaat','postomaat.plugins'],
    scripts = ["src/startscript/postomaat"],
    long_description = """0""" ,
    data_files=[
                ('/etc/postomaat',glob.glob('conf/*.dist')),
                ('/etc/postomaat/conf.d',glob.glob('conf/conf.d/*.dist')),
                ]
) 


#cleanup
if OLD_VERSFILE_CONTENT!=None:
    open(VERSFILE,'w').write(OLD_VERSFILE_CONTENT)
    

