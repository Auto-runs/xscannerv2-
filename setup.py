"""
setup.py — makes XScanner pip-installable.
"""

from setuptools import setup, find_packages

setup(
    name="xscanner",
    version="5.0.0",
    description="Next-Generation XSS Detection Framework",
    python_requires=">=3.11",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.0",
        "httpx>=0.27.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "headless": ["playwright>=1.40.0"],
        "ai":       ["httpx>=0.27.0"],
        "dev":      ["pytest>=7.0.0"],
    },
    entry_points={
        "console_scripts": [
            "xscanner=xscanner:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
)
