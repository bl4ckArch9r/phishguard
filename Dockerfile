FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PHISHGUARD_DB=/data/phishguard.db
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend

# Run as an unprivileged user; /data holds the history database.
RUN useradd -m app && mkdir /data && chown -R app /data /app
USER app
VOLUME /data

WORKDIR /app/backend
EXPOSE 8000
# The container fetches user-supplied URLs: run it with no route to your internal
# network (see README "Deploy safely").
CMD ["uvicorn", "phishguard.main:app", "--host", "0.0.0.0", "--port", "8000"]
