"""
entrypoint_server.py — Ponto de entrada do container do SERVIDOR.

Instancia o VulnerableServer com recursos reais (service_work, conn_mem_kb) a partir
de variaveis de ambiente, escuta em 0.0.0.0:PORT (acessivel pelos outros containers)
e roda continuamente. Ao receber SIGTERM (enviado pelo orquestrador ao final do
experimento), despeja a captura do lado servidor num volume montado e encerra.

Variaveis de ambiente (com defaults):
  HOST=0.0.0.0  PORT=8080  N_WORKERS=30  QUEUE_SIZE=30
  TS_MEAN=0.2   TS_VAR=0.0001  HEADER_BYTES=40
  IDLE_TIMEOUT=(vazio => desligado; defina p/ Slowloris, ex 8)
  SERVICE_WORK=200000   CONN_MEM_KB=256
  OUT_DIR=/data
"""
import csv
import json
import os
import signal
import sys
import threading
import time
from dataclasses import asdict

from server import VulnerableServer


def env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def build_server():
    idle = env("IDLE_TIMEOUT")
    return VulnerableServer(
        host=env("HOST", "0.0.0.0"),
        port=int(env("PORT", "8080")),
        n_workers=int(env("N_WORKERS", "30")),
        queue_size=int(env("QUEUE_SIZE", "30")),
        ts_mean=float(env("TS_MEAN", "0.2")),
        ts_var=float(env("TS_VAR", "0.0001")),
        header_overhead=int(env("HEADER_BYTES", "40")),
        idle_timeout=(float(idle) if idle is not None else None),
        service_work=int(env("SERVICE_WORK", "200000")),
        conn_mem_kb=int(env("CONN_MEM_KB", "256")),
    )


def dump(srv, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    pkts, conn_open, conn_close = srv.capture.snapshot()
    # pacotes (lado servidor)
    with open(os.path.join(out_dir, "server_pkts.csv"), "w", newline="") as f:
        if pkts:
            w = csv.DictWriter(f, fieldnames=list(asdict(pkts[0]).keys()))
            w.writeheader()
            for p in pkts:
                w.writerow(asdict(p))
    # ocupacao e log de requisicoes
    with open(os.path.join(out_dir, "server_occ_events.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "occupied"])
        w.writerows(srv.occ_events)
    with open(os.path.join(out_dir, "server_req_log.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "tag", "seq", "outcome", "occupied_after"])
        w.writerows(srv.req_log)
    with open(os.path.join(out_dir, "server_conn_lifecycle.json"), "w") as f:
        json.dump({"open": conn_open, "close": conn_close, "t0": srv.t0}, f)
    print(f"[server] captura despejada em {out_dir} "
          f"({len(pkts)} pacotes, {len(srv.req_log)} requisicoes)", flush=True)


def occupancy_writer(srv, path, stop):
    """Escreve a ocupacao atual do pool num arquivo, para o orquestrador ler via
    'docker exec cat' (a ocupacao REAL do servidor, alinhavel com o docker stats)."""
    while not stop.is_set():
        try:
            with open(path, "w") as f:
                f.write(str(srv.occupied))
        except OSError:
            pass
        time.sleep(0.2)


def main():
    out_dir = env("OUT_DIR", "/data")
    occ_path = env("OCC_PATH", "/tmp/occ")
    srv = build_server()
    srv.start()
    print(f"[server] escutando em {srv.host}:{srv.port} "
          f"(workers={srv.n_workers} cap={srv.capacity} idle_timeout={srv.idle_timeout} "
          f"service_work={srv.service_work} conn_mem_kb={srv.conn_mem_kb})", flush=True)

    done = threading.Event()
    occ_stop = threading.Event()
    threading.Thread(target=occupancy_writer, args=(srv, occ_path, occ_stop),
                     daemon=True).start()

    def on_term(signum, frame):
        print(f"[server] SIGTERM recebido, encerrando...", flush=True)
        occ_stop.set()
        try:
            dump(srv, out_dir)
        finally:
            srv.stop()
            done.set()

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    while not done.is_set():
        time.sleep(0.5)
    sys.exit(0)


if __name__ == "__main__":
    main()
