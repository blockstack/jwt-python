#!/usr/bin/python2
"""
JSON Tokens
==============

"""

from setuptools import setup, find_packages
import unittest

def get_test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('.', pattern='unit_tests.py')
    return test_suite

setup(
    name='jsontokens',
    version='0.0.4',
    url='https://github.com/blockstack/jsontokens-py',
    license='MIT',
    author='Blockstack Developers',
    author_email='hello@onename.com',
    description=("JSON Web Token Python Library"),
    keywords='json web token sign verify encode decode signature',
    packages=find_packages(),
    zip_safe=False,
    test_suite="setup.get_test_suite",
    install_requires=[
        'cryptography>=1.9',
        'keylib>=0.1.1',
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
