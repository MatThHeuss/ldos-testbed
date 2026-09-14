"""
common.py — utilitários compartilhados do testbed LoRDAS.

Uso educacional / pesquisa. Todo o tráfego é local (loopback).
A segunda constante das gaussianas é VARIÂNCIA, seguindo a notação
N(mean, Var) de Maciá-Fernández et al. (IEEE TIFS, 2009).
"""
import math
import random
import time

# Protocolo mínimo (uma linha por requisição)
RESP_OK = b"OK\n"      # requisição aceita na fila e servida
RESP_BUSY = b"BUSY\n"  # requisição recusada (fila cheia) -> DoS


def sample_positive_normal(mean, var, floor=1e-4):
    """Amostra de N(mean, var) truncada em (floor, +inf). `var` e VARIANCIA."""
    std = math.sqrt(max(var, 0.0))
    x = random.gauss(mean, std)
    return x if x > floor else floor


def now():
    return time.time()


def make_request_line(tag, seq, src_ip="127.0.0.1", hc=1):
    """Ex.: b'GET / TAG=attacker SEQ=3 SRC=10.0.0.5 HC=1\\n'.
    SRC = IP de origem logico (emula host distribuido). HC = requisicao completa."""
    return f"GET / TAG={tag} SEQ={seq} SRC={src_ip} HC={hc}\n".encode()


def parse_request(line: bytes):
    """Retorna (tag, seq, src_ip, http_complete)."""
    tag, seq, src_ip, hc = "unknown", -1, "0.0.0.0", True
    try:
        for part in line.decode(errors="ignore").split():
            if part.startswith("TAG="):
                tag = part[4:]
            elif part.startswith("SEQ="):
                try:
                    seq = int(part[4:])
                except ValueError:
                    seq = -1
            elif part.startswith("SRC="):
                src_ip = part[4:]
            elif part.startswith("HC="):
                hc = (part[3:] != "0")
    except Exception:
        pass
    return tag, seq, src_ip, hc


def ip_pool(prefix, n):
    """Gera n IPs logicos a partir de um prefixo /24 (ex.: prefix='10.0.0')."""
    n = max(1, int(n))
    return [f"{prefix}.{i + 1}" for i in range(n)]



def parse_tag(line: bytes):
    tag, seq = "unknown", -1
    try:
        for part in line.decode(errors="ignore").split():
            if part.startswith("TAG="):
                tag = part[4:]
            elif part.startswith("SEQ="):
                try:
                    seq = int(part[4:])
                except ValueError:
                    seq = -1
    except Exception:
        pass
    return tag, seq
