"""
capture.py — Camada de captura normalizada + utilitarios de feature.

Um PktRecord e o formato canonico de evento de pacote. Tanto o simulador
(server.py instrumentado) quanto um leitor de .pcap real (a adicionar) produzem
PktRecords; o extrator de features (features.py) consome esse formato. Assim o
mesmo pipeline de dataset serve para o testbed local e para capturas do Docker.

Em loopback os IPs reais sao todos 127.0.0.1; por isso a camada carimba cada
conexao com um IP de origem LOGICO (pool configuravel) para emular topologia
distribuida. As portas de origem sao reais (efemeras por conexao).
"""
import math
import threading
from dataclasses import dataclass, field


@dataclass
class PktRecord:
    t: float             # timestamp (epoch)
    src_ip: str          # IP de origem (logico em loopback; real no Docker)
    src_port: int        # porta de origem (efemera real)
    dst_ip: str
    dst_port: int
    size: int            # bytes (payload + overhead de cabecalho modelado)
    is_syn: bool         # inicio de conexao
    tag: str             # attacker | legit
    conn_id: int         # id unico de conexao (lado servidor)
    direction: str       # in (cliente->servidor) | out (servidor->cliente)
    kind: str            # syn | req | resp | rst
    http_complete: bool  # requisicao HTTP completa? (Slowloris => False)


class Capture:
    """Buffer thread-safe de PktRecords, alimentado pelo servidor."""
    def __init__(self):
        self._pkts = []
        self._lock = threading.Lock()
        # ciclo de vida das conexoes: conn_id -> [t_open, t_close]
        self._conn_open = {}
        self._conn_close = {}

    def add(self, rec: PktRecord):
        with self._lock:
            self._pkts.append(rec)

    def open_conn(self, conn_id, t):
        with self._lock:
            self._conn_open[conn_id] = t

    def close_conn(self, conn_id, t):
        with self._lock:
            self._conn_close[conn_id] = t

    def snapshot(self):
        with self._lock:
            return (list(self._pkts), dict(self._conn_open), dict(self._conn_close))


def shannon_entropy(counts):
    """Entropia de Shannon (bits) da distribuicao dada por um dict valor->contagem."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h
