"""Regression tests for the badges displayed in the project README."""

from pathlib import Path
import unittest


README_PATH = Path(__file__).resolve().parents[1] / "README.adoc"


class ReadmeBadgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = README_PATH.read_text(encoding="utf-8")
        cls.badge_block = cls.readme.partition("\n\n")[0]

    def test_unrelated_openssf_best_practices_badge_is_absent(self) -> None:
        self.assertNotIn("bestpractices.dev", self.badge_block)
        self.assertNotIn("OpenSSF Best Practices", self.badge_block)

    def test_unrelated_openssf_project_id_is_absent_from_readme(self) -> None:
        self.assertNotIn("8509", self.readme)

    def test_repository_scoped_openssf_scorecard_badge_remains(self) -> None:
        scorecard_badges = [
            line
            for line in self.badge_block.splitlines()
            if "OpenSSF Scorecard" in line
        ]

        self.assertEqual(1, len(scorecard_badges))
        self.assertIn(
            "api.scorecard.dev/projects/github.com/metadatastician/vordr/badge",
            scorecard_badges[0],
        )
        self.assertIn(
            "scorecard.dev/viewer/?uri=github.com/metadatastician/vordr",
            scorecard_badges[0],
        )

    def test_badge_block_remains_separated_from_document_metadata(self) -> None:
        metadata_start = self.readme.index("// SPDX-License-Identifier")

        self.assertRegex(self.readme[:metadata_start], r"\n{2,}$")


if __name__ == "__main__":
    unittest.main()
