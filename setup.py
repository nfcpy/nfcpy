"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='nfcpy',

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version='0.11.0',

    description='Python module for Near Field Communication',
    long_description=long_description,

    # Project homepage
    url = 'https://launchpad.net/nfcpy',

    # Author details
    author = 'Stephen Tiedemann',
    author_email = 'stephen.tiedemann@gmail.com',

    # License
    license = 'EUPL',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
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

    # Project keywords
    keywords = 'contactless nfc llcp p2p ndef',

    # List of packages
    packages = find_packages(exclude=['docs', 'tests', 'tools']),

    # Run-time dependencies
    install_requires = ['libusb1', 'pyserial', 'docopt'],
)
