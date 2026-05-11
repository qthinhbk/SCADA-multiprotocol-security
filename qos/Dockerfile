FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    iperf3 \
    hping3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY qos_router.py /app/

CMD ["python", "qos_router.py"]
