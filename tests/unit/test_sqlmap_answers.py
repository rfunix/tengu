"""Test for sqlmap --answers flag coverage (P1-4)."""

from __future__ import annotations

import ast
import inspect

from tengu.tools.injection.sqlmap import sqlmap_scan


class TestSqlmapAnswers:
    """P1-4: sqlmap --answers must include 'How many=a' for entry retrieval."""

    def test_answers_flag_contains_how_many(self) -> None:
        """Verify the --answers string includes the 'How many=a' response."""
        source = inspect.getsource(sqlmap_scan)
        tree = ast.parse(source)

        answers_found = False
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "--answers=" in node.value
            ):
                assert "How many=a" in node.value, (
                    f"--answers flag missing 'How many=a': {node.value}"
                )
                answers_found = True

        assert answers_found, "--answers flag not found in sqlmap_scan source"

    def test_answers_flag_contains_keep_testing(self) -> None:
        source = inspect.getsource(sqlmap_scan)
        assert "keep testing=Y" in source

    def test_answers_flag_contains_follow(self) -> None:
        source = inspect.getsource(sqlmap_scan)
        assert "follow=Y" in source
