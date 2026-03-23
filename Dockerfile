# -------------------------
# Base image
# -------------------------
FROM python:3.12-slim

# -------------------------
# Environment variables
# -------------------------
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# -------------------------
# Set working directory
# -------------------------
WORKDIR /app

# -------------------------
# Install dependencies
# -------------------------
COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------
# Copy project files
# -------------------------
COPY . /app/

# -------------------------
# Collect static files
# -------------------------
RUN python manage.py collectstatic --noinput

# -------------------------
# Expose port
# -------------------------
EXPOSE 8000

# -------------------------
# Start server (Daphne)
# -------------------------
CMD ["sh", "-c", "daphne -b 0.0.0.0 -p ${PORT:-8000} config.asgi:application"]