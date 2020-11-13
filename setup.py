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

version_for_setup_py = "0.2.0-1-g168e270"

setup(
    name="asucks",
    version=version_for_setup_py,
    zip_safe=False,
    packages=find_packages(exclude=["test"]),
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
    author_email="tincu.gabriel@gmail.com",
    license="MIT",
    platforms=["POSIX"],
    description="asucks",
    long_description=readme_text,
    url="https://github.com/gabriel-tincu/asucks/",
    python_requires=">=3.7.*",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT Software License",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries",
    ],
)
