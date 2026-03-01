"""Unit tests for GraphQL security checker constants and async functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.api.graphql import (
    _BATCH_QUERIES,
    _DEPTH_QUERY,
    _INTROSPECTION_QUERY,
    _SUGGESTION_QUERY,
    _check_batching,
    _check_depth_limit,
    _check_field_suggestions,
    _check_introspection,
    graphql_security_check,
)

# ---------------------------------------------------------------------------
# TestDepthQuery
# ---------------------------------------------------------------------------


class TestDepthQuery:
    def test_is_string(self):
        assert isinstance(_DEPTH_QUERY, str)

    def test_non_empty(self):
        assert len(_DEPTH_QUERY.strip()) > 0

    def test_deeply_nested(self):
        # Query should have many levels of nesting (at least 5 levels deep)
        assert _DEPTH_QUERY.count("{") >= 5

    def test_contains_typename(self):
        assert "__typename" in _DEPTH_QUERY

    def test_valid_graphql_braces_balanced(self):
        stripped = _DEPTH_QUERY.replace("\n", "").replace(" ", "")
        assert stripped.count("{") == stripped.count("}")


# ---------------------------------------------------------------------------
# TestSuggestionQuery
# ---------------------------------------------------------------------------


class TestSuggestionQuery:
    def test_is_string(self):
        assert isinstance(_SUGGESTION_QUERY, str)

    def test_non_empty(self):
        assert len(_SUGGESTION_QUERY.strip()) > 0

    def test_contains_typo_field(self):
        # Typo in field name to trigger suggestion leak
        assert "__typ" in _SUGGESTION_QUERY


# ---------------------------------------------------------------------------
# TestIntrospectionQuery
# ---------------------------------------------------------------------------


class TestIntrospectionQuery:
    def test_is_string(self):
        assert isinstance(_INTROSPECTION_QUERY, str)

    def test_contains_schema(self):
        assert "__schema" in _INTROSPECTION_QUERY

    def test_contains_types(self):
        assert "types" in _INTROSPECTION_QUERY

    def test_contains_name(self):
        assert "name" in _INTROSPECTION_QUERY


# ---------------------------------------------------------------------------
# TestBatchQueries
# ---------------------------------------------------------------------------


class TestBatchQueries:
    def test_is_list(self):
        assert isinstance(_BATCH_QUERIES, list)

    def test_has_at_least_two_items(self):
        assert len(_BATCH_QUERIES) >= 2

    def test_each_item_has_query_key(self):
        for item in _BATCH_QUERIES:
            assert "query" in item

    def test_each_query_is_string(self):
        for item in _BATCH_QUERIES:
            assert isinstance(item["query"], str)

    def test_first_query_is_introspection(self):
        assert "__schema" in _BATCH_QUERIES[0]["query"]

    def test_second_query_uses_typename(self):
        assert "__typename" in _BATCH_QUERIES[1]["query"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_http_client(post_return_value):
    """Create an async context manager mock for httpx.AsyncClient."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=post_return_value)
    return mock_client


# ---------------------------------------------------------------------------
# TestCheckIntrospection
# ---------------------------------------------------------------------------


class TestCheckIntrospection:
    async def test_introspection_enabled(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"__schema": {"types": [{"name": "Query"}, {"name": "Mutation"}]}}
        }
        mock_client = _make_http_client(mock_resp)

        result = await _check_introspection(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is True
        assert result["severity"] == "high"
        assert result["type_count"] == 2

    async def test_introspection_disabled(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"__schema": {"types": []}}}
        mock_client = _make_http_client(mock_resp)

        result = await _check_introspection(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False
        assert result["type_count"] == 0

    async def test_introspection_exception(self):
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("connection refused"))

        result = await _check_introspection(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# TestCheckBatching
# ---------------------------------------------------------------------------


class TestCheckBatching:
    async def test_batching_enabled(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Response is a list of 2 items (matching _BATCH_QUERIES length)
        mock_resp.json.return_value = [{"data": {}}, {"data": {}}]
        mock_client = _make_http_client(mock_resp)

        result = await _check_batching(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is True
        assert result["severity"] == "medium"

    async def test_batching_disabled(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"errors": [{"message": "Batching not supported"}]}
        mock_client = _make_http_client(mock_resp)

        result = await _check_batching(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False

    async def test_batching_exception(self):
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("network error"))

        result = await _check_batching(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# TestCheckDepthLimit
# ---------------------------------------------------------------------------


class TestCheckDepthLimit:
    async def test_depth_no_limit(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Data returned without depth error → vulnerable
        mock_resp.json.return_value = {"data": {"a": {"b": {}}}, "errors": []}
        mock_client = _make_http_client(mock_resp)

        result = await _check_depth_limit(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is True
        assert result["severity"] == "high"

    async def test_depth_limit_present(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Error mentions "depth" → limit is in place
        mock_resp.json.return_value = {
            "data": None,
            "errors": [{"message": "Query depth limit exceeded"}],
        }
        mock_client = _make_http_client(mock_resp)

        result = await _check_depth_limit(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False

    async def test_depth_exception(self):
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("timeout"))

        result = await _check_depth_limit(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# TestCheckFieldSuggestions
# ---------------------------------------------------------------------------


class TestCheckFieldSuggestions:
    async def test_suggestions_enabled(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "errors": [{"message": "Cannot query field '__typ'. Did you mean '__type'?"}]
        }
        mock_client = _make_http_client(mock_resp)

        result = await _check_field_suggestions(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is True
        assert result["severity"] == "low"

    async def test_suggestions_disabled(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {"errors": [{"message": "Unknown field '__typ'"}]}
        mock_client = _make_http_client(mock_resp)

        result = await _check_field_suggestions(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False

    async def test_suggestions_exception(self):
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=Exception("read timeout"))

        result = await _check_field_suggestions(mock_client, "https://example.com/graphql")
        assert result["vulnerable"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# TestGraphqlSecurityCheck (full function)
# ---------------------------------------------------------------------------


class TestGraphqlSecurityCheck:
    def _make_config_mock(self):
        cfg = MagicMock()
        cfg.tools.defaults.scan_timeout = 30
        return cfg

    def _make_safe_response(self):
        """Response that makes all checks return non-vulnerable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": None,
            "errors": [{"message": "Not available"}],
        }
        return mock_resp

    @patch("tengu.tools.api.graphql.make_allowlist_from_config")
    @patch("tengu.tools.api.graphql.get_audit_logger")
    @patch("tengu.tools.api.graphql.get_config")
    @patch("tengu.tools.api.graphql.httpx.AsyncClient")
    async def test_graphql_blocked_by_allowlist(
        self, mock_httpx, mock_config, mock_audit_fn, mock_allowlist_fn, mock_ctx
    ):
        mock_config.return_value = self._make_config_mock()

        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Not in allowlist")
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Not in allowlist"):
            await graphql_security_check(mock_ctx, "https://example.com/graphql")

        mock_audit.log_target_blocked.assert_awaited_once()

    @patch("tengu.tools.api.graphql.make_allowlist_from_config")
    @patch("tengu.tools.api.graphql.get_audit_logger")
    @patch("tengu.tools.api.graphql.get_config")
    @patch("tengu.tools.api.graphql.httpx.AsyncClient")
    async def test_graphql_all_checks_pass(
        self, mock_httpx, mock_config, mock_audit_fn, mock_allowlist_fn, mock_ctx
    ):
        mock_config.return_value = self._make_config_mock()

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_resp = self._make_safe_response()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_httpx.return_value = mock_client

        result = await graphql_security_check(mock_ctx, "https://example.com/graphql")
        assert result["is_vulnerable"] is False
        assert result["tool"] == "graphql_security_check"
        assert "checks" in result

    @patch("tengu.tools.api.graphql.make_allowlist_from_config")
    @patch("tengu.tools.api.graphql.get_audit_logger")
    @patch("tengu.tools.api.graphql.get_config")
    @patch("tengu.tools.api.graphql.httpx.AsyncClient")
    async def test_graphql_introspection_found(
        self, mock_httpx, mock_config, mock_audit_fn, mock_allowlist_fn, mock_ctx
    ):
        mock_config.return_value = self._make_config_mock()

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        # First call: introspection check returns types list
        intro_resp = MagicMock()
        intro_resp.status_code = 200
        intro_resp.json.return_value = {
            "data": {"__schema": {"types": [{"name": "Query"}, {"name": "String"}]}}
        }

        # Remaining calls: return safe responses
        safe_resp = self._make_safe_response()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[intro_resp, safe_resp, safe_resp])
        mock_httpx.return_value = mock_client

        result = await graphql_security_check(mock_ctx, "https://example.com/graphql")
        assert result["is_vulnerable"] is True
        assert result["checks"]["introspection"]["vulnerable"] is True
        assert len(result["recommendations"]) >= 1

    @patch("tengu.tools.api.graphql.make_allowlist_from_config")
    @patch("tengu.tools.api.graphql.get_audit_logger")
    @patch("tengu.tools.api.graphql.get_config")
    @patch("tengu.tools.api.graphql.httpx.AsyncClient")
    async def test_graphql_authenticated_with_header(
        self, mock_httpx, mock_config, mock_audit_fn, mock_allowlist_fn, mock_ctx
    ):
        mock_config.return_value = self._make_config_mock()

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_resp = self._make_safe_response()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_httpx.return_value = mock_client

        await graphql_security_check(
            mock_ctx,
            "https://example.com/graphql",
            authenticated=True,
            auth_header="Bearer mytoken123",
        )
        # Verify client was created with Authorization header
        call_kwargs = mock_httpx.call_args[1]
        assert "Authorization" in call_kwargs.get("headers", {})
        assert call_kwargs["headers"]["Authorization"] == "Bearer mytoken123"

    @patch("tengu.tools.api.graphql.make_allowlist_from_config")
    @patch("tengu.tools.api.graphql.get_audit_logger")
    @patch("tengu.tools.api.graphql.get_config")
    @patch("tengu.tools.api.graphql.httpx.AsyncClient")
    async def test_graphql_skip_introspection(
        self, mock_httpx, mock_config, mock_audit_fn, mock_allowlist_fn, mock_ctx
    ):
        mock_config.return_value = self._make_config_mock()

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_resp = self._make_safe_response()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_httpx.return_value = mock_client

        result = await graphql_security_check(
            mock_ctx, "https://example.com/graphql", check_introspection=False
        )
        assert "introspection" not in result["checks"]

    @patch("tengu.tools.api.graphql.make_allowlist_from_config")
    @patch("tengu.tools.api.graphql.get_audit_logger")
    @patch("tengu.tools.api.graphql.get_config")
    @patch("tengu.tools.api.graphql.httpx.AsyncClient")
    async def test_graphql_auth_header_strips_newlines(
        self, mock_httpx, mock_config, mock_audit_fn, mock_allowlist_fn, mock_ctx
    ):
        mock_config.return_value = self._make_config_mock()

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_resp = self._make_safe_response()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_httpx.return_value = mock_client

        await graphql_security_check(
            mock_ctx,
            "https://example.com/graphql",
            authenticated=True,
            auth_header="Bearer token\r\nX-Injected: evil",
        )
        call_kwargs = mock_httpx.call_args[1]
        auth = call_kwargs.get("headers", {}).get("Authorization", "")
        assert "\r" not in auth
        assert "\n" not in auth

    @patch("tengu.tools.api.graphql.make_allowlist_from_config")
    @patch("tengu.tools.api.graphql.get_audit_logger")
    @patch("tengu.tools.api.graphql.get_config")
    @patch("tengu.tools.api.graphql.httpx.AsyncClient")
    async def test_graphql_custom_timeout_capped(
        self, mock_httpx, mock_config, mock_audit_fn, mock_allowlist_fn, mock_ctx
    ):
        cfg = MagicMock()
        cfg.tools.defaults.scan_timeout = 300
        mock_config.return_value = cfg

        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_resp = self._make_safe_response()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_httpx.return_value = mock_client

        # timeout=5 → capped to min(5, 30) = 5; timeout=300 → capped to 30
        await graphql_security_check(mock_ctx, "https://example.com/graphql", timeout=300)
        call_kwargs = mock_httpx.call_args[1]
        # Timeout should be capped at 30
        assert call_kwargs.get("timeout") <= 30.0
