#!/usr/bin/env python2.7
from setuptools import setup
from setuptools import find_packages


version = '0.17.0.dev0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'acme=={0}'.format(version),
    'certbot=={0}'.format(version),
    'mock',
    'transip>=0.3.0',
    # For pkg_resources. >=1.0 so pip resolves it to a version cryptography
    # will tolerate; see #2599:
    'setuptools>=1.0',
    'six',
    'zope.interface',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

setup(
    name='certbot-dns-transip',
    version=version,
    description="Transip DNS Authenticator plugin for Certbot",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        'certbot.plugins': [
            'dns-transip = certbot_dns_transip.dns_transip:Authenticator',
        ],
    },
    test_suite='certbot_dns_transip',
)
