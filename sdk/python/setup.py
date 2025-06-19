"""Setup configuration for the Zero Trust Auth Python SDK."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="zerotrust-sdk",
    version="1.0.0",
    author="MVP Team",
    author_email="team@mvp.com",
    description="Python SDK for MVP Zero Trust Authentication system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mvp/zerotrust-auth",
    project_urls={
        "Bug Tracker": "https://github.com/mvp/zerotrust-auth/issues",
        "Documentation": "https://github.com/mvp/zerotrust-auth/wiki",
        "Source Code": "https://github.com/mvp/zerotrust-auth/tree/main/sdk/python",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "types-requests>=2.28.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "responses>=0.21.0",
        ],
    },
    keywords=[
        "zero-trust",
        "authentication",
        "security",
        "sdk",
        "jwt",
        "oauth",
        "api-client",
    ],
    include_package_data=True,
    zip_safe=False,
)