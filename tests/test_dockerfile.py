from policylint import lint_dockerfile
from policylint.core import untagged
from policylint.dockerfile import parse

GOOD = """FROM python:3.12-slim
RUN pip install --no-cache-dir flask
USER app
HEALTHCHECK CMD true
"""


def ids(text):
    return [f.rule for f in lint_dockerfile(text)]


def with_line(text, extra):
    """The clean Dockerfile plus one extra instruction after FROM."""
    lines = text.splitlines()
    return "\n".join([lines[0], extra] + lines[1:]) + "\n"


def test_clean_dockerfile_has_no_findings():
    assert ids(GOOD) == []


def test_each_rule_fires_on_exactly_its_own_problem():
    cases = {
        "DF003": "ADD https://example.com/x.tar.gz /opt/",
        "DF004": "ENV DB_PASSWORD=hunter2",
        "DF005": "RUN curl -sSL https://example.com/install.sh | bash",
        "DF006": "RUN pip install requests",
        "DF008": "RUN apt-get update && apt-get install -y git",
    }
    for rule, line in cases.items():
        assert ids(with_line(GOOD, line)) == [rule], rule
    assert ids(GOOD.replace("python:3.12-slim", "python")) == ["DF001"]
    assert ids(GOOD.replace("USER app\n", "")) == ["DF002"]
    assert ids(GOOD.replace("USER app", "USER root")) == ["DF002"]
    assert ids(GOOD.replace("HEALTHCHECK CMD true\n", "")) == ["DF007"]


def test_safe_variants_are_not_flagged():
    for line in ["ADD ./local.tar.gz /opt/",                               # local ADD is fine
                 "ENV DB_PASSWORD_FILE=/run/secrets/db",                   # a path to a secret, not the secret
                 "ARG API_TOKEN",                                          # declared with no value
                 "ENV API_TOKEN=$BUILD_TOKEN",                             # a reference
                 "RUN curl -fsSL https://example.com/x.tgz -o /tmp/x.tgz && sha256sum -c sums.txt",
                 "RUN apt-get install -y --no-install-recommends git",
                 "ENV TOKENIZERS_PARALLELISM=false TOKEN_TTL=3600"]:        # settings, not secrets
        assert ids(with_line(GOOD, line)) == [], line


def test_image_tag_detection():
    assert untagged("python") and untagged("python:latest") and untagged("localhost:5000/app")
    assert not untagged("python:3.12") and not untagged("localhost:5000/app:1.0")
    assert not untagged("python@sha256:" + "a" * 64)


def test_multistage_only_the_final_stage_must_drop_root():
    text = """FROM golang:1.22 AS build
USER root
RUN go build -o /app .
FROM build AS test
FROM scratch
COPY --from=build /app /app
USER 65534
HEALTHCHECK NONE
"""
    assert ids(text) == ["DF007"]            # root in the build stage is fine; `FROM build` is a stage, not an image
    assert ids(text.replace("USER 65534\n", "")) == ["DF002", "DF007"]


def test_continuation_lines_join_and_report_the_first_line():
    text = "FROM python:3.12\nRUN apt-get update \\\n && apt-get install -y \\\n    git\nUSER app\nHEALTHCHECK CMD true\n"
    assert [(line, kw) for line, kw, _, _ in parse(text)] == [(1, "FROM"), (2, "RUN"), (5, "USER"), (6, "HEALTHCHECK")]
    [finding] = lint_dockerfile(text)
    assert (finding.rule, finding.line) == ("DF008", 2)


def test_ignore_comment_suppresses_one_rule_on_one_instruction():
    above = with_line(GOOD, "# policylint:ignore=DF006\nRUN pip install requests")
    inline = with_line(GOOD, "RUN pip install requests  # policylint:ignore=DF006")
    wrong_rule = with_line(GOOD, "# policylint:ignore=DF008\nRUN pip install requests")
    later = with_line(GOOD, "# policylint:ignore=DF006\nRUN pip install requests\nRUN pip install flask")
    assert ids(above) == [] and ids(inline) == []
    assert ids(wrong_rule) == ["DF006"]
    assert ids(later) == ["DF006"]          # the comment covers only the next instruction


def test_secret_value_is_never_echoed():
    [finding] = lint_dockerfile(with_line(GOOD, "ENV DB_PASSWORD=hunter2"))
    assert "hunter2" not in finding.detail
