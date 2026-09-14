"""
run_slowloris.py — Orquestrador do ataque Slowloris (varredura OFAT + dataset).

Reaproveita o VulnerableServer (agora com idle_timeout=t_k), o LegitClient, o
InfraCollector, a Capture e o extrator de 20 features. Tres fases: benigno ->
ataque (Slowloris segura N_c conexoes) -> recuperacao. Metrica de impacto:
disponibilidade A dos legitimos e ocupacao do pool (as mesmas do LoRDAS).

Varreduras OFAT naturais:
  --sweep Nc    : N_c cruzando a capacidade (saturacao do pool)
  --sweep delta : delta em torno de t_k (delta < t_k funciona; delta > t_k falha)

  python run_slowloris.py --outdir slow_out --sweep Nc --repeats 3
"""
import argparse
import csv
import os
import threading
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from capture import Capture
from common import now
from features import FEATURE_ORDER, extract_windows
from infra import AutoScaler, InfraCollector
from legit_client import LegitClient
import queue_metrics as qm
from server import VulnerableServer
from slowloris_attacker import SlowlorisAttacker


def ip_pool(prefix, n):
    return [f"{prefix}.{i + 1}" for i in range(max(1, n))]


BENIGN_C, ATTACK_C = "#2c7fb8", "#d7301f"


def fig_impacto(ds, p, tag, figdir):
    """A(t) e taxa de recusa por janela, tres fases (benigno/ataque/recuperacao)."""
    def f(x):
        try:
            return float(x)
        except (TypeError, ValueError):
            return None
    x = [f(r["window_start"]) for r in ds]
    A = [f(r["availability_A"]) for r in ds]
    rr = [f(r["refused_rate"]) for r in ds]
    labels = [r["label"] for r in ds]
    onset = next((xi for xi, l in zip(x, labels) if l != "benign"), None)
    end = None
    if onset is not None:
        seen = False
        for xi, l in zip(x, labels):
            if l != "benign":
                seen = True
            elif seen:
                end = xi
                break
    fig, ax = plt.subplots(figsize=(7.4, 4))
    ax.plot(x, A, marker="o", ms=4, color=BENIGN_C, lw=1.8, label=r"$A(t)$ disponibilidade")
    ax.plot(x, rr, marker="s", ms=4, color=ATTACK_C, lw=1.8, label="taxa de recusa")
    hi = end if end is not None else max(x)
    if onset is not None:
        ax.axvspan(min(x), onset, color=BENIGN_C, alpha=0.06)
        ax.axvspan(onset, hi, color=ATTACK_C, alpha=0.08)
        if end is not None:
            ax.axvspan(hi, max(x), color=BENIGN_C, alpha=0.06)
        ax.axvline(onset, color="gray", ls="--", lw=1.3)
        if end is not None:
            ax.axvline(hi, color="gray", ls="--", lw=1.3)
    ax.set_xlabel("tempo (s)")
    ax.set_ylabel("fração")
    ax.set_ylim(-0.03, 1.05)
    ax.set_title(f"Impacto do Slowloris na disponibilidade ({tag})")
    ax.legend(loc="center right")
    fig.tight_layout()
    for e in ("pdf", "png"):
        fig.savefig(os.path.join(figdir, f"slowloris_impacto_{tag}.{e}"), bbox_inches="tight")
    plt.close(fig)
    print(f"  [fig] slowloris_impacto_{tag}")


def fig_sensibilidade(rows, param, figdir, cap, t_k):
    def f(x):
        try:
            return float(x)
        except (TypeError, ValueError):
            return None
    xs = sorted(set(f(r[param]) for r in rows))
    A = []
    for v in xs:
        vals = [f(r["A"]) for r in rows if f(r[param]) == v and r["A"] != ""]
        A.append(sum(vals) / len(vals) if vals else None)
    xlab = {"n_conns": r"$N_c$ (conexões do atacante)", "delta": r"$\delta$ (s)"}.get(param, param)
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(xs, A, marker="o", ms=6, color=BENIGN_C, lw=1.8)
    if param == "n_conns":
        ax.axvline(cap, color=ATTACK_C, ls="--", lw=1.4,
                   label=f"capacidade do pool ({cap:g})")
    elif param == "delta":
        ax.axvline(t_k, color=ATTACK_C, ls="--", lw=1.4, label=f"$t_k$ = {t_k:g} s")
    ax.set_xlabel(xlab)
    ax.set_ylabel(r"$A$ (disponibilidade)")
    ax.set_ylim(-0.03, 1.05)
    ax.set_title(f"Sensibilidade da disponibilidade a {xlab}")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    for e in ("pdf", "png"):
        fig.savefig(os.path.join(figdir, f"slowloris_sensibilidade_{param}.{e}"), bbox_inches="tight")
    plt.close(fig)
    print(f"  [fig] slowloris_sensibilidade_{param}")


def run_scenario(p, outdir, tag=""):
    cap = Capture()
    srv = VulnerableServer(host=p["host"], port=p["port"], n_workers=p["n_workers"],
                           queue_size=p["max_workers"], ts_mean=p["ts_mean"],
                           ts_var=p["ts_var"], header_overhead=p["header_bytes"],
                           idle_timeout=p["t_k"], capture=cap)   # <-- t_k liga o hold
    srv.start()
    time.sleep(0.2)
    port = srv.port

    legit_ips = ip_pool("172.16.0", p["legit_src_ips"])
    legit = LegitClient(host=p["host"], port=port, lam=p["lam"], src_ips=legit_ips) \
        if p["lam"] > 0 else None

    atk = SlowlorisAttacker(host=p["host"], port=port, n_conns=p["n_conns"],
                            delta=p["delta"], src_ip="10.0.0.1",
                            header_bytes=p["header_bytes"],
                            connect_stagger=p["connect_stagger"])

    scaler = AutoScaler(enabled=p["autoscale_enabled"], min_replicas=p["autoscale_min"],
                        max_replicas=p["autoscale_max"],
                        capacity_per_replica=p["autoscale_cap_per_replica"],
                        scale_up_util=p["autoscale_up"], scale_down_util=p["autoscale_down"],
                        cooldown_s=p["autoscale_cooldown"])
    infra = InfraCollector(load_fn=srv.busy_workers, interval=p["infra_interval"],
                           autoscaler=scaler)

    delay = p["attack_start_delay"]
    duration = p["duration"]
    recovery = p["recovery_seconds"]

    t0 = now()
    infra.start()
    legit_th = threading.Thread(target=legit.run, args=(delay + duration + recovery,),
                                daemon=True) if legit else None
    if legit_th:
        legit_th.start()
    if delay > 0:
        time.sleep(delay)                                  # fase benigna
    atk_th = threading.Thread(target=atk.run, args=(duration,), daemon=True)
    atk_th.start()
    atk_th.join()                                          # fase de ataque
    if legit_th:
        legit_th.join()                                    # fase de recuperacao
    t_end = now()
    time.sleep(0.2)
    infra.stop()
    srv.stop()

    C = srv.client_success_probability()
    A, served, sent = (None, None, None)
    if legit:
        A, served, sent = legit.availability()
    occ = qm.occupancy_aggregate(srv.occ_events, srv.capacity)
    ref = qm.refusal_counts(srv.req_log)

    row = {"tag": tag, "n_workers": p["n_workers"], "max_workers": p["max_workers"],
           "n_conns": p["n_conns"], "delta": p["delta"], "t_k": p["t_k"],
           "lam": p["lam"], "duration": duration,
           "atk_msgs": atk.message_count(),
           "atk_rate_Bps": round(atk.mean_rate(duration), 1),
           "C": round(C, 6) if C is not None else "",
           "A": round(A, 6) if A is not None else "",
           "legit_served": served, "legit_sent": sent,
           "occ_mean": round(occ["occ_mean"], 4) if occ["occ_mean"] is not None else "",
           "occ_peak": occ["occ_peak"] if occ["occ_peak"] is not None else "",
           "full_frac": round(occ["full_fraction"], 4) if occ["full_fraction"] is not None else "",
           "refused_total": ref["refused_total"],
           "refused_attacker": ref["refused_attacker"],
           "refused_legit": ref["refused_legit"]}

    pkts, conn_open, conn_close = cap.snapshot()
    legit_log = legit.log if legit else []
    ds = extract_windows(pkts, conn_open, conn_close, legit_log, infra.samples,
                         t0, t_end, p["window_seconds"], attack_label="slowloris")
    with open(os.path.join(outdir, f"dataset_{tag}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FEATURE_ORDER)
        w.writeheader()
        for r in ds:
            w.writerow(r)
    return row, ds


DEFAULTS = {"host": "127.0.0.1", "port": 8080, "n_workers": 30, "max_workers": 30,
            "n_conns": 60, "delta": 2.0, "t_k": 8.0, "lam": 20.0,
            "ts_mean": 0.2, "ts_var": 1e-4, "header_bytes": 40, "connect_stagger": 0.0,
            "attack_start_delay": 5.0, "duration": 40.0, "recovery_seconds": 10.0,
            "window_seconds": 1.0, "legit_src_ips": 16, "infra_interval": 0.25,
            "autoscale_enabled": True, "autoscale_min": 1, "autoscale_max": 8,
            "autoscale_cap_per_replica": 12, "autoscale_up": 0.7, "autoscale_down": 0.3,
            "autoscale_cooldown": 1.0, "seed": 1}


def main():
    ap = argparse.ArgumentParser(description="Ataque Slowloris (OFAT + dataset).")
    ap.add_argument("--outdir", default="slow_out")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--sweep", default="Nc", choices=["Nc", "delta", "none"])
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    cap0 = DEFAULTS["max_workers"]
    sweeps = {
        # N_c cruzando a capacidade (cap0): abaixo, no limiar e acima
        "Nc": [("n_conns", v) for v in [int(0.5 * cap0), int(0.8 * cap0), cap0,
                                        int(1.2 * cap0), int(2 * cap0)]],
        # delta em torno de t_k=8s: menores funcionam, maiores (>t_k) falham
        "delta": [("delta", v) for v in [1.0, 3.0, 6.0, 10.0, 16.0]],
        "none": [(None, None)],
    }[args.sweep]

    rows = []
    ref_ds, ref_p, ref_tag = None, None, None
    port = DEFAULTS["port"]
    for (param, val) in sweeps:
        for rep in range(args.repeats):
            p = dict(DEFAULTS)
            if param:
                p[param] = val
            p["port"] = port
            port += 1
            tag = (f"{param}{val}" if param else "baseline")
            if args.repeats > 1:
                tag += f"__rep{rep}"
            print(f"[run] {tag}  (N_c={p['n_conns']} delta={p['delta']}s t_k={p['t_k']}s "
                  f"cap={p['max_workers']} lam={p['lam']})")
            row, ds = run_scenario(p, args.outdir, tag)
            rows.append(row)
            sat = (param == "n_conns" and val >= p["max_workers"]) or \
                  (param == "delta" and val < p["t_k"]) or param is None
            if ref_ds is None and rep == 0 and sat:
                ref_ds, ref_p, ref_tag = ds, dict(p), tag
            print(f"      -> A={row['A']} C={row['C']} occ_mean={row['occ_mean']}/"
                  f"{p['max_workers']} full={row['full_frac']} "
                  f"ref_legit={row['refused_legit']} | atk_rate={row['atk_rate_Bps']} B/s")

    with open(os.path.join(args.outdir, "results_slowloris.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"\nGravado {len(rows)} cenario(s) em {args.outdir}/results_slowloris.csv")
    figdir = os.path.join(args.outdir, "figuras")
    os.makedirs(figdir, exist_ok=True)
    swept = "n_conns" if args.sweep == "Nc" else ("delta" if args.sweep == "delta" else None)
    if swept:
        fig_sensibilidade(rows, swept, figdir, DEFAULTS["max_workers"], DEFAULTS["t_k"])
    if ref_ds is not None:
        fig_impacto(ref_ds, ref_p, ref_tag, figdir)


if __name__ == "__main__":
    main()
