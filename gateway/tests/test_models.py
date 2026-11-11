"""The model registry and the config.yaml generated from it."""
import os
import sys
import unittest

import yaml

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from croak_models import load_registry, model_list  # noqa: E402
from make_config import render  # noqa: E402

LEVELS = {"none": {}, "low": {"x": 1}, "high": {"x": 2}}


def registry(**model):
    return {"models": {"croak": {"upstream": {"model": "openai/croak"}, **model}}}


class Generated(unittest.TestCase):
    def test_committed_config_matches_the_registry(self):
        rendered = yaml.safe_load(render(os.path.join(HERE, "models.yaml"), os.path.join(HERE, "config.base.yaml")))
        with open(os.path.join(HERE, "config.yaml"), encoding="utf-8") as f:
            committed = yaml.safe_load(f)
        self.assertEqual(rendered, committed, "run: python3 make_config.py -o config.yaml")

    def test_defaults_fill_each_alias_and_entries_override_them(self):
        models = load_registry({"upstream_defaults": {"api_base": "B", "api_key": "K", "timeout": 5},
                                "models": {"a": {"upstream": {"model": "openai/a", "api_key": "K2"}}}})
        self.assertEqual(model_list(models), [{"model_name": "a", "litellm_params": {"model": "openai/a", "api_base": "B", "api_key": "K2", "timeout": 5}}])

    def test_repository_registry_lists_only_croak(self):
        with open(os.path.join(HERE, "models.yaml"), encoding="utf-8") as f:
            models = load_registry(yaml.safe_load(f))
        self.assertEqual([m.name for m in models if m.listed], ["croak"])
        croak = next(m for m in models if m.name == "croak")
        self.assertEqual(croak.reasoning.default, "none")
        self.assertEqual(set(croak.reasoning.levels), {"none", "low", "high"})


class Rejected(unittest.TestCase):
    def check(self, data, message):
        with self.assertRaises(ValueError) as caught:
            load_registry(data)
        self.assertIn(message, str(caught.exception))

    def test_problems_are_named(self):
        self.check({}, "non-empty 'models'")
        self.check({"models": {"a": {}}}, "upstream.model is required")
        self.check(registry(engine="tgi"), "engine must be one of")
        self.check(registry(colour="red"), "unknown keys")
        self.check(registry(reasoning={"levels": {"none": {}, "low": {}}}), "exactly none, low, high")
        self.check(registry(reasoning={"levels": LEVELS, "default": "max"}), "reasoning.default")
        self.check(registry(reasoning={"levels": LEVELS, "max_reasoning_tokens": 0}), "max_reasoning_tokens")
        self.check(registry(limits={"context": -1}), "limits")

    def test_a_base_config_with_its_own_model_list_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            base = os.path.join(d, "base.yaml")
            with open(base, "w") as f:
                f.write("model_list: []\n")
            with self.assertRaises(ValueError):
                render(os.path.join(HERE, "models.yaml"), base)


if __name__ == "__main__":
    unittest.main()
