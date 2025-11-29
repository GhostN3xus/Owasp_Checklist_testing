"""
MOBSCAN Setup Configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "docs" / "MOBSCAN_README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="mobscan",
    version="1.1.0",
    description="Mobile Application Security Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="MOBSCAN Team",
    author_email="security@yourcompany.com",
    url="https://github.com/your-org/mobscan",
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    install_requires=[
        "asyncio>=3.4.3",
        "aiohttp>=3.8.0",
        "aiofiles>=23.0.0",
        "PyYAML>=6.0",
        "pydantic>=2.0.0",
        "python-dotenv>=1.0.0",
        "pytest>=7.4.0",
        "pytest-asyncio>=0.21.0",
        "colorama>=0.4.6",
        "rich>=13.0.0",
        "Jinja2>=3.1.0",
        "markdown>=3.4.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "regex>=2023.0.0",
    ],
    extras_require={
        "frida": [
            "frida>=16.0.0",
            "frida-tools>=12.0.0",
        ],
        "android": [
            "androguard>=3.4.0",
        ],
        "reports": [
            "weasyprint>=59.0",
            "python-docx>=0.8.11",
        ],
        "dev": [
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mobscan=mobscan.cli_professional:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    keywords="mobile security testing android ios apk ipa sast dast sca frida",
    project_urls={
        "Documentation": "https://mobscan.readthedocs.io",
        "Source": "https://github.com/your-org/mobscan",
        "Tracker": "https://github.com/your-org/mobscan/issues",
    },
)
