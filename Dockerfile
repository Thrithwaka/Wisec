# Use a lightweight Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy everything into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port Cloud Run will use
ENV PORT=8080

# Start your Flask app with Gunicorn
CMD exec gunicorn wsgi:app -k eventlet -w 1 -b :$PORT
