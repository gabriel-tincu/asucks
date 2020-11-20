"""
karapace - setup

Copyright (c) 2019 Aiven Ltd
See LICENSE for details
"""
from setuptools import find_packages, setup

import os

readme_path = os.path.join(os.path.dirname(__file__), "README.md")
with open(readme_path, "r") as fp:
    readme_text = fp.read()

version = "0.3.0-dev"

setup(
    name="asucks",
    version=version,
    zip_safe=False,
    packages=find_packages(exclude=["tests"]),
    install_requires=["aiohttp"],
    extras_require={},
    dependency_links=[],
    package_data={},
    entry_points={
        "console_scripts": [
            "asucks = asucks.server:main",
        ],
    },
    author="Tincu Gabriel",
    author_email="gabri@aiven.io",
    license="MIT",
    platforms=["POSIX"],
    description="asucks",
    long_description=readme_text,
    url="https://github.com/aiven/asucks/",
    python_requires=">=3.7.*",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT Software License",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries",
    ],
)
