"""
run_experiment.py — Orquestrador do testbed LoRDAS (loopback / pesquisa).

Sobe servidor + trafego legitimo + atacante, coleta captura normalizada e
metricas de infra, e grava:
  - results/results.csv           : uma linha por cenario (A, C, O agregados)
  - results/packets_<tag>.csv     : eventos brutos (debug/inspecao)
  - results/dataset_<tag>.csv     : FEATURES POR JANELA, rotuladas (dataset p/ ML)

Fase benigna opcional (attack_start_delay) gera janelas 'benign' antes do
atacante entrar, produzindo as duas classes num unico experimento.
"""
import argparse
import csv
import itertools
import os
import threading
import time

import yaml

from attacker import LordasAttacker
from capture import Capture
from common import ip_pool, now
from features import FEATURE_ORDER, extract_windows
from infra import AutoScaler, InfraCollector
from legit_client import LegitClient
from server import VulnerableServer
import queue_metrics as qm

METRIC_KEYS = ["n_workers", "queue_size", "ts_mean", "ts_var", "delta",
               "t_ontime", "t_offtime", "rtt_mean", "rtt_var", "lam", "duration"]


def run_scenario(p, outdir, tag=""):
    p = dict(p)
    if p.get("queue_equals_workers"):
        p["queue_size"] = p["n_workers"]   # mantem fila = N_s (evita fila < workers)
    cap = Capture()
    srv = VulnerableServer(host=p["host"], port=p["port"], n_workers=p["n_workers"],
                           queue_size=p["queue_size"], ts_mean=p["ts_mean"],
                           ts_var=p["ts_var"], header_overhead=p["header_overhead_bytes"],
                           capture=cap)
    srv.start()
    time.sleep(0.2)
    port = srv.port

    atk_ips = ip_pool("10.0.0", p["attacker_src_ips"])
    legit_ips = ip_pool("172.16.0", p["legit_src_ips"])

    atk = LordasAttacker(host=p["host"], port=port, delta=p["delta"],
                         t_ontime=p["t_ontime"], t_offtime=p["t_offtime"],
                         rtt_mean=p["rtt_mean"], rtt_var=p["rtt_var"],
                         n_workers_hint=p["n_workers"], calibrate_n=p["calibrate_n"],
                         use_replies=p["use_replies"], use_bursts=p["use_bursts"],
                         sync_mode=p.get("sync_mode", "freerate"), src_ips=atk_ips)
    ts_m, ts_v = atk.calibrate()          # servidor ocioso (antes da janela t0)

    legit = None
    if p["lam"] > 0 and not p["c_only"]:
        legit = LegitClient(host=p["host"], port=port, lam=p["lam"], src_ips=legit_ips)

    # auto-scaler + coletor de infra (proxies de docker stats/exec)
    scaler = AutoScaler(enabled=p["autoscale_enabled"], min_replicas=p["autoscale_min"],
                        max_replicas=p["autoscale_max"],
                        capacity_per_replica=p["autoscale_cap_per_replica"],
                        scale_up_util=p["autoscale_up"], scale_down_util=p["autoscale_down"],
                        cooldown_s=p["autoscale_cooldown"])
    infra = InfraCollector(load_fn=srv.busy_workers, interval=p["infra_interval"],
                           autoscaler=scaler)

    duration = p["duration"]
    delay = p.get("attack_start_delay", 0.0)
    recovery = p.get("recovery_seconds", 0.0)

    # t0 das janelas = inicio do trafego legitimo (apos calibracao)
    t0 = now()
    infra.start()
    legit_th = threading.Thread(target=legit.run, args=(delay + duration + recovery,), daemon=True) if legit else None
    if legit_th:
        legit_th.start()
    if delay > 0:
        time.sleep(delay)                  # fase benigna
    atk_th = threading.Thread(target=atk.run, args=(duration,), daemon=True)
    atk_th.start()
    atk_th.join()
    if legit_th:
        legit_th.join()
    t_end = now()
    time.sleep(0.2)
    infra.stop()
    srv.stop()

    # ---- indicadores agregados (results.csv) ----
    C = srv.client_success_probability()
    A = served = sent = None
    if legit:
        A, served, sent = legit.availability()
    atk_rate = atk.attack_rate(duration)
    max_accept_rate = p["n_workers"] / max(ts_m, 1e-6)
    O_rate = atk_rate / max_accept_rate if max_accept_rate > 0 else None
    n_pkts_period = int(p["t_ontime"] / p["delta"]) + 1
    Pu = A if A is not None else None
    O_eq31 = (n_pkts_period + (1 - Pu)) if Pu is not None else None

    # ---- metricas AUXILIARES de fila (reporte; nao entram no dataset) ----
    occ_agg = qm.occupancy_aggregate(srv.occ_events, srv.capacity)
    ref_cnt = qm.refusal_counts(srv.req_log)

    row = {
        "tag": tag, **{k: p[k] for k in METRIC_KEYS},
        "T_ef": round(p["t_ontime"] + p["t_offtime"], 6),
        "duty_cycle": round(p["t_ontime"] / (p["t_ontime"] + p["t_offtime"]), 4),
        "ts_est_mean": round(ts_m, 6), "ts_est_var": round(ts_v, 8),
        "C": round(C, 6) if C is not None else "",
        "A": round(A, 6) if A is not None else "",
        "attack_msgs": atk.attack_message_count(), "attack_rate": round(atk_rate, 3),
        "O_rate_ratio": round(O_rate, 4) if O_rate is not None else "",
        "O_eq31_count": round(O_eq31, 4) if O_eq31 is not None else "",
        "queue_occ_mean": round(occ_agg["occ_mean"], 4) if occ_agg["occ_mean"] is not None else "",
        "queue_occ_peak": occ_agg["occ_peak"] if occ_agg["occ_peak"] is not None else "",
        "queue_full_frac": round(occ_agg["full_fraction"], 4) if occ_agg["full_fraction"] is not None else "",
        "refused_total": ref_cnt["refused_total"],
        "refused_attacker": ref_cnt["refused_attacker"],
        "refused_legit": ref_cnt["refused_legit"],
    }

    # ---- dataset por janela (dataset.csv) ----
    pkts, conn_open, conn_close = cap.snapshot()
    legit_log = legit.log if legit else []
    ds_rows = extract_windows(pkts, conn_open, conn_close, legit_log, infra.samples,
                              t0, t_end, p["window_seconds"], attack_label=p.get("label", "lordas"))
    ds_path = os.path.join(outdir, f"dataset_{tag}.csv")
    with open(ds_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FEATURE_ORDER)
        w.writeheader()
        for r in ds_rows:
            w.writerow(r)

    q_rows = qm.occupancy_windows(srv.occ_events, srv.req_log, srv.capacity,
                                  t0, t_end, p["window_seconds"])
    with open(os.path.join(outdir, f"queue_{tag}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=qm.QUEUE_FIELDS)
        w.writeheader()
        for r in q_rows:
            w.writerow(r)

    if p.get("write_packet_log", True):
        _write_packet_log(os.path.join(outdir, f"packets_{tag}.csv"), pkts, legit_log)

    n_atk = sum(1 for r in ds_rows if r["label"] != "benign")
    n_ben = len(ds_rows) - n_atk
    return row, (len(ds_rows), n_ben, n_atk)


def _write_packet_log(path, pkts, legit_log):
    rows = [(p.t, p.direction, p.kind, p.tag, p.src_ip, p.src_port, p.size,
             int(p.is_syn), int(p.http_complete), p.conn_id) for p in pkts]
    rows.sort(key=lambda r: r[0])
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "direction", "kind", "tag", "src_ip", "src_port",
                    "size", "is_syn", "http_complete", "conn_id"])
        for r in rows:
            w.writerow([f"{r[0]:.6f}", *r[1:]])


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def expand_sweeps(cfg):
    """Gera (tag, params) por cenario.

    sweep_mode:
      - "ofat" (um fator por vez): baseline + variar UM parametro de cada vez, os
        demais no baseline. Cresce linearmente. Reproduz a metodologia da Fig. 9.
      - "grid" (produto cartesiano): todas as combinacoes. Cresce multiplicativamente.
    """
    base = dict(cfg["defaults"])
    sweeps = cfg.get("sweep") or {}
    mode = str(base.get("sweep_mode", "grid")).lower()
    if not sweeps:
        yield "single", base
        return

    if mode == "ofat":
        yield "baseline", dict(base)
        for k, values in sweeps.items():
            for v in values:
                if v == base.get(k):
                    continue                    # valor == baseline: ja coberto
                q = dict(base)
                q[k] = v
                yield f"{k}{v}", q
    else:  # grid / cartesiano
        keys = list(sweeps.keys())
        for combo in itertools.product(*[sweeps[k] for k in keys]):
            q = dict(base)
            parts = []
            for k, v in zip(keys, combo):
                q[k] = v
                parts.append(f"{k}{v}")
            yield "_".join(parts), q


DEFAULTS = {
    "use_replies": True, "use_bursts": True, "c_only": False, "write_packet_log": True,
    "sync_mode": "freerate", "window_seconds": 1.0, "attack_start_delay": 0.0,
    "label": "lordas", "attacker_src_ips": 1, "legit_src_ips": 16,
    "header_overhead_bytes": 40, "infra_interval": 0.2, "autoscale_enabled": True,
    "autoscale_min": 1, "autoscale_max": 10, "autoscale_cap_per_replica": 4,
    "autoscale_up": 0.8, "autoscale_down": 0.3, "autoscale_cooldown": 1.0,
    "sweep_mode": "grid", "queue_equals_workers": False, "recovery_seconds": 0.0,
}


def main():
    ap = argparse.ArgumentParser(description="Testbed LoRDAS local (loopback, pesquisa).")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--outdir", default="results")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--seed", type=int, default=None,
                    help="semente base; cada rodada usa seed+indice (reprodutibilidade parcial)")
    ap.add_argument("--plots", action="store_true", help="gera figuras ao final")
    ap.add_argument("--figdir", default="figuras")
    for k in ["host", "port", "n_workers", "queue_size", "ts_mean", "ts_var", "delta",
              "t_ontime", "t_offtime", "rtt_mean", "rtt_var", "lam", "duration",
              "calibrate_n", "window_seconds", "attack_start_delay", "attacker_src_ips",
              "legit_src_ips"]:
        ap.add_argument(f"--{k}")
    ap.add_argument("--c-only", action="store_true")
    ap.add_argument("--no-replies", action="store_true")
    ap.add_argument("--no-bursts", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)
    os.makedirs(args.outdir, exist_ok=True)
    d = cfg["defaults"]
    for k, v in DEFAULTS.items():
        d.setdefault(k, v)

    for k in ["host", "port", "n_workers", "queue_size", "ts_mean", "ts_var", "delta",
              "t_ontime", "t_offtime", "rtt_mean", "rtt_var", "lam", "duration",
              "calibrate_n", "window_seconds", "attack_start_delay", "attacker_src_ips",
              "legit_src_ips"]:
        v = getattr(args, k)
        if v is not None:
            d[k] = type(d[k])(v)
    if args.c_only:
        d["c_only"] = True
    if args.no_replies:
        d["use_replies"] = False
    if args.no_bursts:
        d["use_bursts"] = False

    all_rows = []
    idx = 0
    for name, params in expand_sweeps(cfg):
        for r in range(args.repeats):
            params = dict(params)
            params["port"] = int(params["port"]) + idx
            if args.seed is not None:
                import random as _rnd
                _rnd.seed(args.seed + idx)   # amostras deterministicas (ver ressalva no README)
            idx += 1
            tag = f"{name}__rep{r}" if args.repeats > 1 else name
            print(f"[run] {tag}  (T_s={params['ts_mean']} N_s={params['n_workers']} "
                  f"Δ={params['delta']} t_on={params['t_ontime']} λ={params['lam']} "
                  f"dur={params['duration']}s benign={params['attack_start_delay']}s)")
            row, (nw, nb, na) = run_scenario(params, args.outdir, tag=tag)
            all_rows.append(row)
            print(f"      -> C={row['C']} A={row['A']} O(rate)={row['O_rate_ratio']} "
                  f"msgs={row['attack_msgs']} | janelas={nw} (benign={nb}, ataque={na})")

    if all_rows:
        results_path = os.path.join(args.outdir, "results.csv")
        keys = list(all_rows[0].keys())
        with open(results_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for row in all_rows:
                w.writerow(row)
        print(f"\nGravado {len(all_rows)} cenario(s) em {results_path}")
        print(f"Datasets por janela em {args.outdir}/dataset_<tag>.csv")

    if args.plots:
        try:
            from plots import generate_all
            print()
            generate_all(args.outdir, args.figdir)
        except Exception as e:
            print(f"[plots] falha ao gerar figuras: {e}")


if __name__ == "__main__":
    main()
