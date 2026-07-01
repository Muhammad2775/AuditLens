from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENTRY = ROOT / "Program Files" / "AuditLens.py"

class ImportResolutionTests(unittest.TestCase):
    def test_entrypoint_imports_and_resolves_sample_path(self):
        spec = importlib.util.spec_from_file_location("auditlens_entry", ENTRY)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        parser = module.build_arg_parser()
        args = parser.parse_args([])

        self.assertTrue(args.input.exists())
        self.assertTrue(args.input.is_dir())

if __name__ == "__main__":
    unittest.main()
