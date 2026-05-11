FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y iptables iproute2 procps tcpdump && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY firewall_monitor.py /app/
COPY firewall_rules.sh /app/
COPY active_blocker.py /app/
COPY whitelist.conf /app/

COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
