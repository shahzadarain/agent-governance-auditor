# Deliberately unsafe: floating tag, runs as root.
FROM python:latest
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY agent.py .
CMD ["python", "agent.py"]
