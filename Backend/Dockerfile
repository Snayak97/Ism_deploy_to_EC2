# ------------------------
# BASE IMAGE
# ------------------------
FROM python:3.11-slim

# Prevent Python buffer issues
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# ------------------------
# SYSTEM DEPENDENCIES
# ------------------------
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# ------------------------
# INSTALL PYTHON DEPENDENCIES
# ------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ------------------------
# COPY PROJECT CODE
# ------------------------
COPY . .

# ------------------------
# EXPOSE INTERNAL PORT
# ------------------------
EXPOSE 5000

# ------------------------
# START GUNICORN (Production)
# Works for both local + EC2
# ------------------------
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "run:app"]
