
# python setup.py --dry-run --verbose install

import os.path
from setuptools import setup, find_packages
from distutils.command.install_scripts import install_scripts
import ssl
# from version import tag_version

# ssl._create_default_https_context = ssl._create_unverified_context

# python setup.py install --record files.txt

from distutils.core import setup


setup(
    name='whoshere',
    version='0.1.20170710',
    #version=tag_version,
    author='Peter Shipley',
    author_email='Peter.Shipley@gmail.com',
    packages=find_packages(),
    scripts=['/whoshere-isy/whoshere-isy.py', '/whoshere-iftt/whoshere-iftt.py'],
    # url='https://github.com/evilpete/',
    # git='git@bitbucket.org:evilpete/scapy-watch.git',
    license='BSD',
    download_url='https://bitbucket.org/evilpete/scapy-watch/get/master.tar.gz',
    description='Monitor hosts on local lan.',
    # long_description=open('README.txt').read(),
    # cmdclass = { 'install_scripts': install_scripts_and_symlinks }
    install_requires=['scapy'],
    entry_points={
          'console_scripts': [
              # 'whoshere-isy = whoshere.whoshere_isy:main',
              'whoshere = whoshere.whoshere_main:main'
          ],
      }
)

