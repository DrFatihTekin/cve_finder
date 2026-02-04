from setuptools import setup, find_packages

setup(
    name="cve-finder",
    version="1.0.0",
    description="Fetch CVEs per application from NVD (CVE API 2.0)",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(exclude=("build", "dist")),
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "cve-finder=cve_finder.cli:main",
        ],
    },
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
