"""Tier-1 + PBT tests for Phase 4 extractors and classifier."""

from __future__ import annotations

import unittest

from hypothesis import given
from hypothesis import strategies as st

from strix.core.inventory.classify import (
    agent_classify_param,
    classify_endpoint,
    classify_param,
)
from strix.core.inventory.extractors import (
    extract_form_params,
    extract_js_params,
    extract_openapi_params,
    extract_proxy_params,
    merge_extracted_params,
)
from strix.core.inventory.models import Endpoint, Param, ParamObservation


class TestProxyExtractor(unittest.TestCase):
    """Proxy records yield query, header, and body parameters."""

    def test_extracts_query_params(self) -> None:
        records = [{"request": {"url": "https://api.example.com/items?q=foo&limit=10"}}]
        params = extract_proxy_params(records)
        self.assertEqual(set(params), {"q", "limit"})
        self.assertIn("foo", params["q"].example_values)
        self.assertEqual(params["q"].location, "query")

    def test_extracts_headers(self) -> None:
        records = [
            {
                "request": {
                    "url": "https://api.example.com/items",
                    "headers": {"Authorization": "bearer x"},
                },
            }
        ]
        params = extract_proxy_params(records)
        self.assertIn("Authorization", params)
        self.assertEqual(params["Authorization"].location, "header")

    def test_extracts_json_body_params(self) -> None:
        records = [
            {
                "request": {
                    "url": "https://api.example.com/items",
                    "body": {"name": "widget", "price": 10},
                },
            }
        ]
        params = extract_proxy_params(records)
        self.assertIn("name", params)
        self.assertEqual(params["name"].location, "body")

    def test_extracts_form_body_params(self) -> None:
        records = [
            {
                "request": {
                    "url": "https://api.example.com/items",
                    "body": "name=widget&price=10",
                },
            }
        ]
        params = extract_proxy_params(records)
        self.assertIn("name", params)
        self.assertEqual(params["name"].location, "body")


class TestOpenAPIExtractor(unittest.TestCase):
    """OpenAPI spec parameters are extracted by location."""

    def test_extracts_operation_parameters(self) -> None:
        spec = {
            "paths": {
                "/items": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query"},
                            {"name": "Authorization", "in": "header"},
                        ]
                    }
                }
            }
        }
        params = extract_openapi_params(spec)
        self.assertEqual(params["q"].location, "query")
        self.assertEqual(params["Authorization"].location, "header")


class TestJSExtractor(unittest.TestCase):
    """JS patterns reveal query, formData, and JSON body candidates."""

    def test_extracts_query_keys(self) -> None:
        source = "fetch('/api/items?q=' + term + '&limit=10')"
        params = extract_js_params(source)
        self.assertEqual(set(params), {"q", "limit"})
        self.assertEqual(params["q"].location, "query")

    def test_extracts_form_data_keys(self) -> None:
        source = "formData.append('file', file); formData.set('name', name)"
        params = extract_js_params(source)
        self.assertEqual(set(params), {"file", "name"})
        self.assertEqual(params["file"].location, "body")

    def test_extracts_json_body_keys(self) -> None:
        source = "fetch('/api/items', { body: JSON.stringify({ name: 'x', price: 1 }) })"
        params = extract_js_params(source)
        self.assertEqual(set(params), {"name", "price"})
        self.assertEqual(params["name"].location, "body")


class TestFormExtractor(unittest.TestCase):
    """HTML form tags yield body parameters."""

    def test_extracts_input_textarea_select_names(self) -> None:
        html = """
        <form>
            <input name="username" />
            <textarea name="bio"></textarea>
            <select name="role"></select>
        </form>
        """
        params = extract_form_params(html)
        self.assertEqual(set(params), {"username", "bio", "role"})
        self.assertEqual(params["username"].location, "body")


class TestMergeExtractedParams(unittest.TestCase):
    """Merging unions provenance and example values."""

    def test_merge_unions_provenance_and_examples(self) -> None:
        existing = {"q": ParamObservation(name="q", location="query", provenance=["openapi"])}
        extracted = {
            "q": ParamObservation(
                name="q", location="query", provenance=["proxy"], example_values=["x"]
            ),
        }
        merged = merge_extracted_params(existing, extracted)
        self.assertEqual(sorted(merged["q"].provenance), ["openapi", "proxy"])
        self.assertEqual(merged["q"].example_values, ["x"])

    def test_merge_adds_new_params(self) -> None:
        existing = {"q": ParamObservation(name="q", location="query")}
        extracted = {"limit": ParamObservation(name="limit", location="query", provenance=["js"])}
        merged = merge_extracted_params(existing, extracted)
        self.assertIn("limit", merged)
        self.assertEqual(merged["limit"].provenance, ["js"])


class TestClassifier(unittest.TestCase):
    """Baseline classification is deterministic and records evidence."""

    def test_object_id_classification(self) -> None:
        param = Param(name="user_id", location="query")
        evidence = classify_param(param)
        self.assertEqual(evidence.class_name, "object-id")
        self.assertIn("user_id", evidence.evidence)

    def test_file_classification(self) -> None:
        param = Param(name="upload", location="body")
        evidence = classify_param(param)
        self.assertEqual(evidence.class_name, "file")

    def test_path_param_defaults_to_object_id(self) -> None:
        param = Param(name="item", location="path")
        evidence = classify_param(param)
        self.assertEqual(evidence.class_name, "object-id")

    def test_unknown_classification(self) -> None:
        param = Param(name="foo", location="query")
        evidence = classify_param(param)
        self.assertEqual(evidence.class_name, "unknown")

    def test_classify_endpoint_attaches_evidence(self) -> None:
        endpoint = Endpoint(key="k", method="GET", url="https://api.example.com/items")
        endpoint.params["user_id"] = Param(name="user_id", location="query")
        classify_endpoint(endpoint)
        evidence = endpoint.params["user_id"].class_evidence
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.class_name, "object-id")  # type: ignore[union-attr]

    def test_agent_override(self) -> None:
        param = Param(name="foo", location="query")
        agent_classify_param(param, "html", "manual review")
        self.assertEqual(param.class_evidence.class_name, "html")  # type: ignore[union-attr]
        self.assertEqual(param.class_evidence.evidence, "manual review")  # type: ignore[union-attr]


class TestClassificationPBT(unittest.TestCase):
    """Classification determinism invariant."""

    @given(st.sampled_from(["id", "user_id", "file", "upload", "role", "amount", "url", "foo"]))
    def test_classifier_is_deterministic(self, name: str) -> None:
        param = Param(name=name, location="query")
        first = classify_param(param)
        second = classify_param(param)
        self.assertEqual(first.class_name, second.class_name)
        self.assertEqual(first.evidence, second.evidence)
