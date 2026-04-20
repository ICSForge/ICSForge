"""Run the detection generator as a module:
  python -m icsforge.detection   --outdir out/detections
"""
import sys

from icsforge.detection.generator import main

sys.exit(main())
