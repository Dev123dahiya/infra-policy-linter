from __future__ import annotations

import re

from .core import Finding, secret_like, untagged

IGNORE = re.compile(r"#\s*policylint:ignore=([A-Z0-9,]+)")


def parse(text: str) -> list[tuple[int, str, str, set[str]]]:
    """Split a Dockerfile into (line number, INSTRUCTION, arguments, ignored rule ids).

    Joins backslash continuations, so a RUN spread over ten lines is one
    instruction reported at its first line. A `# policylint:ignore=ID` comment
    on the line above an instruction, or at the end of it, suppresses that rule there.
    """
    instructions = []
    buffer, start, ignored, pending = "", 0, set(), set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        mark = IGNORE.search(line)
        if line.startswith("#") or not line:
            if mark and not buffer:
                pending |= set(mark.group(1).split(","))
            continue
        if mark:
            ignored |= set(mark.group(1).split(","))
            line = line[:mark.start()].rstrip()
        if not buffer:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        keyword, _, rest = buffer.partition(" ")
        instructions.append((start, keyword.upper(), rest.strip(), ignored | pending))
        buffer, ignored, pending = "", set(), set()
    return instructions


def lint_dockerfile(text: str, path: str = "Dockerfile") -> list[Finding]:
    instructions = parse(text)
    findings: list[Finding] = []

    def report(rule: str, line: int, detail: str, ignored: set[str]) -> None:
        if rule not in ignored:
            findings.append(Finding(rule, path, line, "", detail))

    stages: set[str] = set()
    user, user_line, last_from, last_from_ignored = None, 0, 0, set()
    has_healthcheck = False
    for line, keyword, rest, ignored in instructions:
        if keyword == "FROM":
            parts = rest.split()
            image = next((p for p in parts if not p.startswith("--")), "")
            # A later stage may build FROM an earlier one by name; that is not an image pull.
            if image and image != "scratch" and image.lower() not in stages and "$" not in image and untagged(image):
                report("DF001", line, f"FROM {image}", ignored)
            if len(parts) >= 3 and parts[-2].upper() == "AS":
                stages.add(parts[-1].lower())
            # Only the final stage ships, so USER and HEALTHCHECK state restarts at each FROM.
            user, user_line, last_from, last_from_ignored, has_healthcheck = None, line, line, ignored, False
        elif keyword == "USER":
            user, user_line = rest.split(":")[0].strip(), line
        elif keyword == "HEALTHCHECK":
            has_healthcheck = rest.upper() != "NONE"
        elif keyword == "ADD":
            if re.search(r"\bhttps?://", rest):
                report("DF003", line, f"ADD {rest.split()[0]}", ignored)
        elif keyword in ("ENV", "ARG"):
            for name, value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S*)", rest) or [tuple((rest.split(None, 1) + [""])[:2])]:
                value = value.strip("\"'")
                if secret_like(name, value) and not name.upper().endswith(("_FILE", "_PATH")):
                    report("DF004", line, f"{keyword} {name}=<redacted>", ignored)
        elif keyword == "RUN":
            if re.search(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", rest):
                report("DF005", line, "download piped to a shell", ignored)
            if re.search(r"\bpip3?\s+install\b", rest) and "--no-cache-dir" not in rest:
                report("DF006", line, "pip install", ignored)
            if re.search(r"\bapt-get\s+(-\S+\s+)*install\b", rest) and "--no-install-recommends" not in rest:
                report("DF008", line, "apt-get install", ignored)

    if instructions and last_from:
        if user is None:
            report("DF002", last_from, "final stage never sets USER", last_from_ignored)
        elif user in ("root", "0"):
            report("DF002", user_line, f"USER {user}", next((i for l, k, r, i in instructions if l == user_line), set()))
        if not has_healthcheck:
            report("DF007", last_from, "final stage has no HEALTHCHECK", last_from_ignored)
    return sorted(findings, key=lambda f: (f.line, f.rule))
