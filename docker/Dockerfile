FROM python:3.12-slim

LABEL maintainer="ICSForge Contributors"
LABEL description="ICSForge — OT/ICS Coverage Validation Framework"

WORKDIR /app

# Install dependencies first (Docker cache layer)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . /app

# Create output directories
RUN mkdir -p /app/out/pcaps /app/out/events /app/receiver_out

EXPOSE 8080

CMD ["python", "-m", "icsforge.web.app", "--host", "0.0.0.0", "--port", "8080"]
