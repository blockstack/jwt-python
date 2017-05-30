"""
JSON Tokens
==============

"""

from setuptools import setup, find_packages

setup(
    name='jsontokens',
    version='0.0.3',
    url='https://github.com/blockstack/jwt-py',
    license='MIT',
    author='Blockstack Developers',
    author_email='hello@onename.com',
    description=("JSON Web Token Python Library"),
    keywords='json web token sign verify encode decode signature',
    packages=find_packages(),
    zip_safe=False,
    install_requires=[
        'cryptography>=1.9',
        'keylib>=0.0.2',
        'requests>=2.9.1',
        'utilitybelt>=0.2.6'
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
