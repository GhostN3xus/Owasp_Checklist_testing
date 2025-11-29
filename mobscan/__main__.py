"""
MOBSCAN - Mobile Application Security Testing Framework
Entry point for command-line execution.

Usage:
    python -m mobscan scan app.apk
    python -m mobscan --help
"""

from mobscan.cli_professional import main

if __name__ == '__main__':
    main()
