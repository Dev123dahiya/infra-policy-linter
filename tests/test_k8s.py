import copy
import json
import os

import yaml

from policylint import RULES, lint_manifest, lint_path
from policylint.__main__ import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GOOD = {
    "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"},
    "spec": {"template": {"spec": {
        "securityContext": {"runAsNonRoot": True},
        "containers": [{
            "name": "app", "image": "nginx:1.27",
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
            "readinessProbe": {"httpGet": {"path": "/", "port": 80}},
        }],
    }}},
}


def ids(doc):
    return [f.rule for f in lint_manifest(yaml.safe_dump(doc))]


def changed(edit):
    """The clean Deployment with one change applied to (pod spec, container)."""
    doc = copy.deepcopy(GOOD)
    spec = doc["spec"]["template"]["spec"]
    edit(spec, spec["containers"][0])
    return doc


def test_clean_deployment_has_no_findings():
    assert ids(GOOD) == []


def test_each_rule_fires_on_exactly_its_own_problem():
    cases = {
        "K8S001": lambda s, c: c["securityContext"].update(privileged=True),
        "K8S002": lambda s, c: c["securityContext"].pop("allowPrivilegeEscalation"),
        "K8S003": lambda s, c: s.pop("securityContext"),
        "K8S004": lambda s, c: c["resources"]["limits"].pop("memory"),
        "K8S005": lambda s, c: c.update(image="nginx"),
        "K8S006": lambda s, c: s.update(hostPID=True),
        "K8S007": lambda s, c: s.update(volumes=[{"name": "h", "hostPath": {"path": "/etc"}}]),
        "K8S008": lambda s, c: c.pop("readinessProbe"),
        "K8S009": lambda s, c: c.update(env=[{"name": "API_KEY", "value": "abc123"}]),
        "K8S010": lambda s, c: c["securityContext"].pop("capabilities"),
    }
    assert set(cases) == {r for r in RULES if r.startswith("K8S")}       # every K8s rule has a case
    for rule, edit in cases.items():
        assert ids(changed(edit)) == [rule], rule


def test_safe_variants_are_not_flagged():
    safe = [
        lambda s, c: c.update(env=[{"name": "API_KEY", "valueFrom": {"secretKeyRef": {"name": "x", "key": "k"}}}]),
        lambda s, c: c.update(env=[{"name": "TOKEN_TTL", "value": "3600"}]),
        lambda s, c: s.update(volumes=[{"name": "tmp", "emptyDir": {}}]),
        lambda s, c: s.update(hostNetwork=False),
        lambda s, c: (s.pop("securityContext"), c["securityContext"].update(runAsUser=1000)),   # a non-zero uid also proves non-root
        lambda s, c: c.update(image="nginx@sha256:" + "a" * 64),
    ]
    for edit in safe:
        assert ids(changed(edit)) == []


def test_container_setting_overrides_pod_setting():
    assert ids(changed(lambda s, c: c["securityContext"].update(runAsNonRoot=False))) == ["K8S003"]
    assert ids(changed(lambda s, c: c["securityContext"].update(runAsUser=0))) == ["K8S003"]


def test_every_workload_kind_is_checked_and_other_kinds_ignored():
    pod_spec = {"containers": [{"name": "c", "image": "busybox"}]}
    docs = [
        {"kind": "Pod", "metadata": {"name": "a"}, "spec": pod_spec},
        {"kind": "StatefulSet", "metadata": {"name": "b"}, "spec": {"template": {"spec": pod_spec}}},
        {"kind": "CronJob", "metadata": {"name": "c"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": pod_spec}}}}},
        {"kind": "Service", "metadata": {"name": "d"}, "spec": {"ports": [{"port": 80}]}},
        {"kind": "ConfigMap", "metadata": {"name": "e"}, "data": {"password": "x"}},
    ]
    findings = lint_manifest(yaml.safe_dump_all(docs))
    assert {f.resource.split()[0] for f in findings} == {"Pod/a", "StatefulSet/b", "CronJob/c"}


def test_init_containers_are_checked_but_do_not_need_probes():
    doc = changed(lambda s, c: s.update(initContainers=[{"name": "migrate", "image": "app:1.0"}]))
    found = [f for f in lint_manifest(yaml.safe_dump(doc)) if "container=migrate" in f.resource]
    assert [f.rule for f in found] == ["K8S002", "K8S004", "K8S010"]


def test_findings_point_at_the_right_line_and_container():
    text = open(os.path.join(ROOT, "examples", "bad", "deployment.yaml")).read()
    by_rule = {f.rule: f for f in lint_manifest(text, "deployment.yaml")}
    lines = text.splitlines()
    assert "hostNetwork" in lines[by_rule["K8S006"].line - 1]
    assert "name: api" in lines[by_rule["K8S001"].line - 1]
    assert "DB_PASSWORD" in lines[by_rule["K8S009"].line - 1]
    assert by_rule["K8S001"].resource == "Deployment/payments container=api"
    assert "hunter2" not in json.dumps([f.as_dict() for f in by_rule.values()])


def test_annotation_suppresses_listed_rules_for_that_resource_only():
    doc = changed(lambda s, c: (c.pop("readinessProbe"), c["resources"].pop("limits")))
    assert ids(doc) == ["K8S004", "K8S008"]
    doc["metadata"]["annotations"] = {"policylint/ignore": "K8S004, K8S008"}
    other = changed(lambda s, c: c.pop("readinessProbe"))
    other["metadata"]["name"] = "other"
    findings = lint_manifest(yaml.safe_dump_all([doc, other]))
    assert [(f.rule, f.resource.split()[0]) for f in findings] == [("K8S008", "Deployment/other")]


def test_example_directories_and_exit_codes(capsys):
    bad, _, _ = lint_path(os.path.join(ROOT, "examples", "bad"))
    assert {f.rule for f in bad} == set(RULES)                 # the bad examples trip all 18 rules
    assert lint_path(os.path.join(ROOT, "examples", "good"))[0] == []
    assert main([os.path.join(ROOT, "examples", "good")]) == 0
    assert main([os.path.join(ROOT, "examples", "bad")]) == 1
    assert main([os.path.join(ROOT, "Dockerfile"), "--fail-on", "low"]) == 0     # this repo's own Dockerfile
    capsys.readouterr()
    assert main([os.path.join(ROOT, "examples", "bad"), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["files_checked"] == 2 and len(report["findings"]) == 18


def test_fail_on_threshold_and_unparseable_files(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER app\n")          # only DF007, which is low
    assert main([str(tmp_path)]) == 0
    assert main([str(tmp_path), "--fail-on", "low"]) == 1
    (tmp_path / "chart.yaml").write_text("replicas: {{ .Values.replicas }}\nimage: {{ .Values.image }}:x\n  bad: [")
    findings, checked, errors = lint_path(str(tmp_path))
    assert checked == 1 and len(errors) == 1 and errors[0].startswith("chart.yaml")
