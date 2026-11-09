#!/usr/bin/env python3
"""Checks policy.yaml against opencode agent permissions before a deploy.

An agent whose profile allows personal data (pii: allow) must not be able to
send it elsewhere: webfetch, websearch and bash must be denied in its
~/.config/opencode/agent/<agent>.md. Exits 1 and lists the problems otherwise.
"""
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from croak_core import load_policy  # noqa: E402

EXFIL_TOOLS = ("webfetch", "websearch", "bash")


def agent_permissions(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    front = yaml.safe_load(m.group(1)) if m else {}
    return (front or {}).get("permission") or {}


def main(policy_path, agent_dir):
    with open(policy_path, encoding="utf-8") as f:
        policy = load_policy(yaml.safe_load(f) or {})
    problems = []
    for agent, profile in policy.agents.items():
        if policy.profiles[profile].pii != "allow":
            continue
        path = os.path.join(agent_dir, f"{agent}.md")
        if not os.path.exists(path):
            problems.append(f"{agent}: profile {profile} allows pii but {path} does not exist")
            continue
        perms = agent_permissions(path)
        for tool in EXFIL_TOOLS:
            if perms.get(tool) != "deny":
                problems.append(f"{agent}: profile {profile} allows pii, so '{tool}' must be deny (now {perms.get(tool)!r})")
    for p in problems:
        print("policy check:", p)
    print("policy check:", "ok" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "policy.yaml",
                  sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/.config/opencode/agent")))
