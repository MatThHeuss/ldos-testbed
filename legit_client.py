"""
legit_client.py — Trafego legitimo com chegadas de Poisson (taxa agregada λ).

Mede a disponibilidade A e o tempo de resposta RT. Cada requisicao legitima usa
um IP de origem logico de um pool (emula muitos usuarios distintos) e envia
requisicoes HTTP completas.
"""
import random
import socket
import threading

from common import RESP_OK, make_request_line, now


class LegitClient:
    def __init__(self, host="127.0.0.1", port=8080, lam=20.0, src_ips=None,
                 max_outstanding=512):
        self.host, self.port = host, port
        self.lam = lam
        self.src_ips = list(src_ips) if src_ips else ["172.16.0.1"]
        self.seq = 0
        self.running = threading.Event()
        self.sem = threading.Semaphore(max_outstanding)
        self.log = []   # (t_send, seq, outcome, rt)
        self.log_lock = threading.Lock()

    def _one(self, seq):
        if not self.sem.acquire(blocking=False):
            with self.log_lock:
                self.log.append((now(), seq, "dropped_client", 0.0))
            return
        t_send = now()
        outcome, rt = "error", 0.0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60.0)
            s.connect((self.host, self.port))
            s.sendall(make_request_line("legit", seq, random.choice(self.src_ips), 1))
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(64)
                if not chunk:
                    break
                data += chunk
            rt = now() - t_send
            outcome = "served" if data.startswith(RESP_OK) else "refused"
            s.close()
        except OSError:
            rt = now() - t_send
            outcome = "error"
        finally:
            self.sem.release()
        with self.log_lock:
            self.log.append((t_send, seq, outcome, rt))

    def run(self, duration):
        self.running.set()
        t_end = now() + duration
        while now() < t_end and self.running.is_set():
            threading.Event().wait(random.expovariate(self.lam))
            self.seq += 1
            threading.Thread(target=self._one, args=(self.seq,), daemon=True).start()
        self.running.clear()
        threading.Event().wait(0.2)

    def availability(self):
        served = sum(1 for r in self.log if r[2] == "served")
        sent = sum(1 for r in self.log if r[2] in ("served", "refused"))
        A = (served / sent) if sent > 0 else None
        return A, served, sent
