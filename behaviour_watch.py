"""Start Behaviour Watch from anywhere:  python behaviour_watch.py serve <folder>   (same commands as `python -m watch`)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from watch.__main__ import main  # noqa: E402

if __name__ == "__main__":
    main()
