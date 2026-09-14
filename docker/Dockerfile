# Imagem unica do testbed LDoS. Os modulos de runtime (server, common, capture,
# legit_client, attacker, slowloris_attacker) usam apenas a biblioteca padrao do
# Python, entao nao ha pip install. O papel do container e escolhido pelo
# 'command' no docker-compose (entrypoint_server.py, entrypoint_attacker.py, etc).
FROM python:3.12-slim

WORKDIR /app

# codigo do projeto (raiz) + entrypoints do docker
COPY *.py /app/
COPY docker/entrypoint_*.py /app/

ENV PYTHONUNBUFFERED=1

# papel padrao: servidor (sobrescreva com 'command' no compose para outros papeis)
CMD ["python", "entrypoint_server.py"]
