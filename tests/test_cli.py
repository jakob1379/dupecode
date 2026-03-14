import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "dupecode.py"


class DupecodeCliTest(unittest.TestCase):
    def run_dupecode(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        )

    def test_text_output_when_scanning_self(self) -> None:
        result = self.run_dupecode("dupecode.py")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dupecode v0.1.0", result.stdout)
        self.assertIn("Score: 100/100 (Grade: A+)", result.stdout)
        self.assertIn("Files: 1 | Lines: 619 | Duplicated: 0 (0.0%)", result.stdout)
        self.assertIn("Clone groups: 0 (0 exact, 0 parameterized)", result.stdout)

    def test_json_output_when_scanning_self(self) -> None:
        result = self.run_dupecode("--json", "dupecode.py")

        self.assertEqual(result.returncode, 0, result.stderr)

        payload = json.loads(result.stdout)
        self.assertEqual(
            payload,
            {
                "version": "0.1.0",
                "score": 100,
                "grade": "A+",
                "total_lines": 619,
                "duplicated_lines": 0,
                "duplication_pct": 0.0,
                "files_scanned": 1,
                "clone_groups": 0,
                "clones": [],
            },
        )


if __name__ == "__main__":
    unittest.main()
