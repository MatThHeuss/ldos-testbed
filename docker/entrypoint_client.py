"""
entrypoint_client.py — Ponto de entrada dos containers CLIENTES (papel via ROLE).

ROLE=legit      -> LegitClient (mede disponibilidade dos usuarios legitimos)
ROLE=slowloris  -> SlowlorisAttacker
ROLE=lordas     -> LordasAttacker

Cada papel conecta no servidor (SERVER_HOST:SERVER_PORT, o nome do servico na rede
Docker), roda por DURATION segundos (ou ate SIGTERM), e despeja seus resultados num
volume montado (OUT_DIR). O orquestrador no host controla as fases iniciando/parando
estes containers no momento certo.

Env comuns: ROLE, SERVER_HOST=server, SERVER_PORT=8080, DURATION, OUT_DIR=/data
Env por papel:
  legit:     LAM=20, LEGIT_SRC_IPS=16
  slowloris: N_CONNS=60, DELTA=2.0, HEADER_BYTES=40
  lordas:    DELTA=0.005, T_ONTIME=0.01, T_OFFTIME=0.02, LORDAS_SRC_IPS=1,
             CALIBRATE_N=10, N_WORKERS_HINT=8
"""
import csv
import json
import os
import signal
import sys
import threading

from common import now


def env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def ip_pool(prefix, n):
    return [f"{prefix}.{i + 1}" for i in range(max(1, int(n)))]


def build():
    role = env("ROLE", "legit")
    host = env("SERVER_HOST", "server")
    port = int(env("SERVER_PORT", "8080"))

    if role == "legit":
        from legit_client import LegitClient
        obj = LegitClient(host=host, port=port, lam=float(env("LAM", "20")),
                          src_ips=ip_pool("172.16.0", env("LEGIT_SRC_IPS", "16")))

        def dump(out_dir):
            with open(os.path.join(out_dir, "legit_log.csv"), "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["t_send", "seq", "outcome", "rt"])
                w.writerows(obj.log)
            A, served, sent = obj.availability()
            with open(os.path.join(out_dir, "legit_summary.json"), "w") as f:
                json.dump({"A": A, "served": served, "sent": sent}, f)
            print(f"[legit] A={A} served={served} sent={sent} "
                  f"({len(obj.log)} eventos)", flush=True)
        return role, obj, dump

    if role == "slowloris":
        from slowloris_attacker import SlowlorisAttacker
        obj = SlowlorisAttacker(host=host, port=port,
                                n_conns=int(env("N_CONNS", "60")),
                                delta=float(env("DELTA", "2.0")),
                                src_ip=env("ATTACKER_SRC_IP", "10.0.0.1"),
                                header_bytes=int(env("HEADER_BYTES", "40")))

        def dump(out_dir):
            dur = float(env("DURATION", "1"))
            with open(os.path.join(out_dir, "attacker_stats.json"), "w") as f:
                json.dump({"role": "slowloris", "msgs": obj.message_count(),
                           "mean_rate_Bps": obj.mean_rate(dur)}, f)
            print(f"[slowloris] msgs={obj.message_count()} "
                  f"rate={obj.mean_rate(dur):.1f} B/s", flush=True)
        return role, obj, dump

    if role == "lordas":
        from attacker import LordasAttacker
        obj = LordasAttacker(host=host, port=port,
                             delta=float(env("DELTA", "0.005")),
                             t_ontime=float(env("T_ONTIME", "0.01")),
                             t_offtime=float(env("T_OFFTIME", "0.02")),
                             calibrate_n=int(env("CALIBRATE_N", "10")),
                             n_workers_hint=int(env("N_WORKERS_HINT", "8")),
                             src_ips=ip_pool("10.0.0", env("LORDAS_SRC_IPS", "1")),
                             allow_nonloopback=True)  # alvo = container proprio

        def dump(out_dir):
            stats = {"role": "lordas"}
            if hasattr(obj, "message_count"):
                stats["msgs"] = obj.message_count()
            with open(os.path.join(out_dir, "attacker_stats.json"), "w") as f:
                json.dump(stats, f)
            print(f"[lordas] {stats}", flush=True)
        return role, obj, dump

    raise SystemExit(f"ROLE desconhecido: {role}")


def main():
    out_dir = env("OUT_DIR", "/data")
    os.makedirs(out_dir, exist_ok=True)
    duration = float(env("DURATION", "1000000"))
    role, obj, dump = build()
    print(f"[{role}] iniciando contra {obj.host}:{obj.port} por {duration}s", flush=True)

    dumped = threading.Event()

    def do_dump():
        if not dumped.is_set():
            dumped.set()
            dump(out_dir)

    def on_term(signum, frame):
        print(f"[{role}] SIGTERM recebido", flush=True)
        # para o cliente legitimo de forma limpa, se aplicavel
        if hasattr(obj, "running"):
            obj.running.clear()
        do_dump()
        sys.exit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    th = threading.Thread(target=obj.run, args=(duration,), daemon=True)
    th.start()
    th.join()          # termina quando a duracao expira
    do_dump()          # despeja apos conclusao normal
    sys.exit(0)


if __name__ == "__main__":
    main()
