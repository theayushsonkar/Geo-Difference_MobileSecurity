#!/usr/bin/env python3
"""
scan_manifest.py
────────────────
Thin entry-point script for the modular manifest_scanner package.
"""

import sys
from manifest_scanner import main

if __name__ == "__main__":
    sys.exit(main())
