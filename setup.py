"""
Setup configuration for CrypticGen package.
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="crypticgen",
    version="1.0.0",
    author="Kushal V",
    author_email="kushalvgowda7@gmail.com",
    description="A secure and powerful password generation and management utility",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "crypticgen=crypticgen.cli:main",  
        ],
    },

    install_requires=[
        "requests >=2.20.0"
    ],
)