FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY firewall_monitor.py /app/
COPY firewall_rules.sh /app/
COPY active_blocker.py /app/
COPY whitelist.conf /app/

CMD ["sh", "-c", "bash /app/firewall_rules.sh && (python /app/firewall_monitor.py & python /app/active_blocker.py & wait)"]
