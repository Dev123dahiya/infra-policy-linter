FROM python
ENV API_TOKEN=abc123def456
ADD https://example.com/tool.tar.gz /opt/
RUN apt-get update && apt-get install -y curl
RUN curl -sSL https://example.com/install.sh | sh
COPY . /app
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/main.py"]
