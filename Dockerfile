# A command-line tool that exits when done: there is no server to health-check.
# policylint:ignore=DF007
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY policylint ./policylint
RUN pip install --no-cache-dir .
RUN useradd --create-home appuser
USER appuser
ENTRYPOINT ["python", "-m", "policylint"]
CMD ["/src"]
