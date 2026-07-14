FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iptables iproute2 curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend /app
RUN pip install --no-cache-dir .
ENV EXITLANE_DATA_DIR=/data
EXPOSE 8787
CMD ["uvicorn","exitlane.main:app","--host","0.0.0.0","--port","8787"]
