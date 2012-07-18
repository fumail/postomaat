from distutils.core import setup
import glob
import sys
sys.path.insert(0,'src')
from postomaat import POSTOMAAT_VERSION

setup(name = "postomaat",
    version = POSTOMAAT_VERSION,
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
