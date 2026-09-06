"""Double-click launcher for the packaged .exe.

Runs the same app as `python -m lan_device_manager`, but with no arguments so it
starts the dashboard and opens the browser - the behaviour a non-technical user
expects from an executable.
"""

import sys

from lan_device_manager.__main__ import main

if __name__ == "__main__":
    sys.exit(main(["--host", "127.0.0.1"]))
