#!/usr/bin/env python3
"""
Setup script for Virtual HSM Python library
"""

from setuptools import setup, find_packages
import os


# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Python bindings for Virtual HSM"


setup(
    name='vhsm',
    version='2.0.0',
    description='Python bindings for Virtual HSM - Cryptographic key management library',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Virtual HSM Contributors',
    author_email='',
    url='https://github.com/ahillelt/virtual_hsm',
    packages=find_packages(),
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    keywords='hsm cryptography security encryption signatures',
    install_requires=[
        # No external dependencies - uses ctypes
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov>=4.0',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/ahillelt/virtual_hsm/issues',
        'Source': 'https://github.com/ahillelt/virtual_hsm',
    },
)
