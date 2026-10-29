FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml ./
COPY pii ./pii
RUN pip install . && useradd --uid 10001 --no-create-home app
USER app
ENV PORT=8080
CMD ["sh", "-c", "exec uvicorn pii.api:app_factory --factory --host 0.0.0.0 --port ${PORT}"]
