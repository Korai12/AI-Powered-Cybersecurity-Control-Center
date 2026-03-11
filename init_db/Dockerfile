FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY init_db/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code so we can run Alembic and access seed data
COPY ../backend /app/backend

COPY . .

CMD ["python", "init_db/init.py"]
