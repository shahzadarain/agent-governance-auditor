# Pinned to an exact version tag. For stronger assurance, pin by digest:
#   FROM python:3.12.6-slim-bookworm@sha256:<digest you have verified>
FROM python:3.12.6-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY triage_agent/ ./triage_agent/

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent
USER 10001:10001

ENTRYPOINT ["python", "-m", "triage_agent"]
