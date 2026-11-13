from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# rule id -> (severity, what is wrong, why it matters)
RULES: dict[str, tuple[str, str, str]] = {
    "DF001": ("medium", "Base image has no fixed tag", "`latest` changes under you: two builds of one commit can ship different code"),
    "DF002": ("high", "Container runs as root", "A process that escapes the app is root inside the container, and often on the host"),
    "DF003": ("medium", "ADD fetches a remote URL", "The download is unverified and uncached; use COPY, or RUN curl with a checksum"),
    "DF004": ("high", "Secret baked into the image", "ENV and ARG values are stored in image layers and readable by anyone who pulls it"),
    "DF005": ("high", "Remote script piped straight into a shell", "Whatever the server returns at build time runs as root, unreviewed"),
    "DF006": ("low", "pip install without --no-cache-dir", "The download cache stays in the layer and enlarges the image"),
    "DF007": ("low", "No HEALTHCHECK", "The runtime cannot tell a hung process from a healthy one"),
    "DF008": ("medium", "apt-get install without --no-install-recommends", "Pulls in optional packages, growing the image and its attack surface"),
    "K8S001": ("high", "Privileged container", "Privileged mode disables almost all isolation from the host"),
    "K8S002": ("high", "Privilege escalation not disabled", "Without allowPrivilegeEscalation: false, a setuid binary can gain more rights than the process started with"),
    "K8S003": ("high", "May run as root", "Neither the pod nor the container sets runAsNonRoot: true"),
    "K8S004": ("medium", "No CPU or memory limit", "One leaking container can starve every other pod on the node"),
    "K8S005": ("medium", "Image has no fixed tag", "A restart may silently pull a different version"),
    "K8S006": ("high", "Shares a host namespace", "hostNetwork, hostPID or hostIPC lets the pod see or reach host processes and traffic"),
    "K8S007": ("high", "Mounts a host path", "hostPath volumes expose the node's filesystem to the pod"),
    "K8S008": ("low", "No liveness or readiness probe", "Traffic is sent to pods that are not ready, and hung pods are never restarted"),
    "K8S009": ("high", "Secret written as a literal env value", "It is visible in the manifest and in `kubectl describe`; use secretKeyRef"),
    "K8S010": ("medium", "Capabilities not dropped", "Containers keep default Linux capabilities they almost never need; drop ALL and add back specifics"),
}

SECRET_NAME = re.compile(r"(?i)(passw(or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)")
NOT_A_SECRET = re.compile(r"(?i)^(true|false|yes|no|on|off|none|null|\d+(\.\d+)?)$")


def secret_like(name: str, value) -> bool:
    """A credential-like name holding a literal value. Flags and numbers
    (TOKENIZERS_PARALLELISM=false, TOKEN_TTL=3600) are settings, not secrets."""
    value = "" if value is None else str(value)
    return bool(SECRET_NAME.search(name)) and value != "" and not value.startswith("$") and not NOT_A_SECRET.match(value)


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    resource: str        # e.g. "Deployment/web container=api", or "" for Dockerfiles
    detail: str

    @property
    def severity(self) -> str:
        return RULES[self.rule][0]

    @property
    def title(self) -> str:
        return RULES[self.rule][1]

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "title": self.title, "path": self.path, "line": self.line,
                "resource": self.resource, "detail": self.detail, "why": RULES[self.rule][2]}


def untagged(image: str) -> bool:
    """True when an image reference can change between pulls: no tag, or the `latest` tag.

    A digest (name@sha256:...) is the most fixed reference there is. The colon
    in a registry port (localhost:5000/app) is not a tag.
    """
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return True
    return last.rsplit(":", 1)[1] == "latest"
