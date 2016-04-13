"""Setup module for nfcpy.
"""

from setuptools import setup, find_packages
from codecs import open
from os import path
import re

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, 'nfc', '__init__.py'), encoding='utf-8') as f:
    match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", f.read(), re.M)
    if not match:
        raise RuntimeError("Unable to find version string.")
    version_string = match.group(1)
    if not re.match(r"\d+\.\d+\.\d+$", version_string):
        raise RuntimeError("This is not a release version.")

setup(
    name = 'nfcpy',
    version = version_string,
    packages = find_packages(exclude=['examples']),
    license = 'EUPL',
    url = 'https://launchpad.net/nfcpy',

    description = 'Python module for Near Field Communication',
    long_description = long_description,
    keywords = 'contactless nfc llcp p2p ndef',

    author = 'Stephen Tiedemann',
    author_email = 'stephen.tiedemann@gmail.com',

    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: European Union Public Licence 1.1 (EUPL 1.1)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers',
        'Environment :: Console',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],

    install_requires = ['libusb1', 'pyserial'],
)
