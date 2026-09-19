# The approval API (ADR-0001's second service).
#
# Only the `api` extra is installed. The image therefore has no LangGraph model client, no Docker
# client and no GitHub write path — the service cannot start a scan or open a pull request even if
# a bug tried to, because the code to do either is not present.
#
# The worker is NOT this image. It needs Docker, the model client and a GitHub token, and in the
# demo deployment it runs as a GitHub Actions job rather than a container.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -e ".[api,postgres]"

# Run as a non-root user: nothing here needs to write to the image.
RUN useradd --create-home --uid 10001 patchpilot
USER patchpilot

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import httpx,os,sys; sys.exit(0 if httpx.get(f'http://127.0.0.1:{os.environ.get(\"PORT\",8000)}/health',timeout=4).status_code==200 else 1)"

CMD ["sh", "-c", "uvicorn patchpilot.api.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
