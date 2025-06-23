"""
Setup configuration for keycloak-zerotrust Python package.
"""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# Read version from __init__.py
def get_version():
    version = {}
    with open(os.path.join(this_directory, 'keycloak_zerotrust', '__init__.py')) as f:
        exec(f.read(), version)
    return version['__version__']

setup(
    name='keycloak-zerotrust',
    version=get_version(),
    author='Zero Trust Team',
    author_email='team@yourorg.com',
    description='Python client library for Keycloak Zero Trust authentication',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourorg/go-keycloak-zerotrust',
    packages=find_packages(exclude=['tests*']),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
    python_requires='>=3.8',
    install_requires=[
        'httpx>=0.25.0',
        'pydantic>=2.0.0',
        'pyjwt[crypto]>=2.8.0',
        'python-jose[cryptography]>=3.3.0',
        'redis>=5.0.0',
        'pydantic-settings>=2.0.0',
        'typing-extensions>=4.0.0',
        'asyncio-throttle>=1.0.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0',
            'pytest-cov>=4.0.0',
            'pytest-mock>=3.10.0',
            'httpx-mock>=0.11.0',
            'black>=23.0.0',
            'isort>=5.12.0',
            'flake8>=6.0.0',
            'mypy>=1.5.0',
            'pre-commit>=3.0.0',
        ],
        'fastapi': [
            'fastapi>=0.100.0',
            'uvicorn>=0.23.0',
        ],
        'django': [
            'django>=4.2.0',
            'djangorestframework>=3.14.0',
        ],
        'flask': [
            'flask>=2.3.0',
            'flask-cors>=4.0.0',
        ],
        'starlette': [
            'starlette>=0.27.0',
        ],
        'all': [
            'fastapi>=0.100.0',
            'uvicorn>=0.23.0',
            'django>=4.2.0',
            'djangorestframework>=3.14.0',
            'flask>=2.3.0',
            'flask-cors>=4.0.0',
            'starlette>=0.27.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'keycloak-zerotrust=keycloak_zerotrust.cli:main',
        ],
    },
    project_urls={
        'Bug Reports': 'https://github.com/yourorg/go-keycloak-zerotrust/issues',
        'Source': 'https://github.com/yourorg/go-keycloak-zerotrust',
        'Documentation': 'https://go-keycloak-zerotrust.readthedocs.io/',
    },
    keywords='keycloak zero-trust authentication security jwt oidc',
    include_package_data=True,
    zip_safe=False,
)