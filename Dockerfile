FROM python:3.12-slim

RUN apt-get clean && apt-get -y update

RUN apt-get -y install \
    nginx \
    python3-dev \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt --src /usr/local/src

COPY . .

# Expose port
EXPOSE 8080
EXPOSE 5000

# CMD ["flask", "run", "--host=0.0.0.0", "--port=8080"]
CMD ["python", "app.py"]