from __future__ import annotations

import yaml

from .core import Finding, secret_like, untagged

LINE = "__line__"


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that remembers the source line of every mapping, so findings can point at it."""


def _mapping(loader, node, deep=False):
    data = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    data[LINE] = node.start_mark.line + 1
    return data


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)

# Where the pod template lives inside each workload kind.
POD_SPEC_PATH = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"), "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"), "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}


def _dig(obj, path):
    for key in path:
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj if isinstance(obj, dict) else None


def lint_manifest(text: str, path: str = "manifest.yaml") -> list[Finding]:
    """Check every workload in a (possibly multi-document) manifest.

    Suppress rules for one resource with the annotation
    `policylint/ignore: "K8S004,K8S008"`.
    """
    findings: list[Finding] = []
    for doc in yaml.load_all(text, Loader=_LineLoader):
        if not isinstance(doc, dict) or doc.get("kind") not in POD_SPEC_PATH:
            continue
        kind, meta = doc["kind"], doc.get("metadata") or {}
        spec = _dig(doc, POD_SPEC_PATH[kind])
        if spec is None:
            continue
        ignored = {r.strip() for r in str((meta.get("annotations") or {}).get("policylint/ignore", "")).split(",")}
        name = f"{kind}/{meta.get('name', '?')}"

        def report(rule, line, detail, resource=name):
            if rule not in ignored:
                findings.append(Finding(rule, path, line, resource, detail))

        shared = [flag for flag in ("hostNetwork", "hostPID", "hostIPC") if spec.get(flag) is True]
        if shared:
            report("K8S006", spec[LINE], ", ".join(shared))
        for volume in spec.get("volumes") or []:
            if isinstance(volume, dict) and "hostPath" in volume:
                host = volume["hostPath"]
                report("K8S007", volume[LINE], f"volume {volume.get('name', '?')} -> {host.get('path', '?') if isinstance(host, dict) else host}")

        pod_ctx = spec.get("securityContext") or {}
        # Init containers run to completion before the app starts, so probes do not apply to them.
        groups = [(c, True) for c in spec.get("containers") or []] + [(c, False) for c in spec.get("initContainers") or []]
        for container, long_running in groups:
            if not isinstance(container, dict):
                continue
            who, line = f"{name} container={container.get('name', '?')}", container[LINE]
            ctx = container.get("securityContext") or {}
            if ctx.get("privileged") is True:
                report("K8S001", line, "securityContext.privileged: true", who)
            if ctx.get("allowPrivilegeEscalation") is not False:
                report("K8S002", line, "allowPrivilegeEscalation is not false", who)
            # The container-level value overrides the pod-level one.
            non_root = ctx.get("runAsNonRoot", pod_ctx.get("runAsNonRoot"))
            uid = ctx.get("runAsUser", pod_ctx.get("runAsUser"))
            if uid == 0 or (non_root is not True and not (isinstance(uid, int) and uid > 0)):
                report("K8S003", line, "runAsUser: 0" if uid == 0 else "runAsNonRoot is not true", who)
            limits = (container.get("resources") or {}).get("limits") or {}
            missing = [r for r in ("cpu", "memory") if r not in limits]
            if missing:
                report("K8S004", line, "no limit for " + " or ".join(missing), who)
            image = str(container.get("image", ""))
            if untagged(image):
                report("K8S005", line, f"image: {image or '(none)'}", who)
            if long_running and "livenessProbe" not in container and "readinessProbe" not in container:
                report("K8S008", line, "no probes", who)
            for env in container.get("env") or []:
                if isinstance(env, dict) and secret_like(str(env.get("name", "")), env.get("value")):
                    report("K8S009", env[LINE], f"env {env['name']}=<redacted>", who)
            dropped = [str(c).upper() for c in ((ctx.get("capabilities") or {}).get("drop") or [])]
            if "ALL" not in dropped:
                report("K8S010", line, "capabilities.drop does not include ALL", who)
    return sorted(findings, key=lambda f: (f.line, f.rule))
