# Multi-stage build for small image size
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "-m", "crucible"]