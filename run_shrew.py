"""
run_shrew.py — Orquestrador do simulador Shrew (varredura OFAT + dataset + figuras).

Reproduz a resposta em frequencia do artigo (Fig. 4): throughput normalizado vs T,
com nulos em T = minRTO e minRTO/2. Gera:
  - results_shrew.csv        : uma linha por cenario (rho por fase, taxa media, etc.)
  - dataset_<tag>.csv        : as 20 features por janela (mesmo pipeline do LoRDAS)
  - figuras/shrew_resposta_frequencia.(pdf|png)  : rho(T) simulado vs Eq. (2)
  - figuras/shrew_impacto_<tag>.(pdf|png)        : throughput(t), tres fases
"""
import argparse
import csv
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from features import FEATURE_ORDER, extract_windows
from shrew_sim import ShrewSim

BENIGN_C, ATTACK_C = "#2c7fb8", "#d7301f"


def eq2(T, minrto):
    return (math.ceil(minrto / T) * T - minrto) / T


def run_scenario(p, tag, outdir, want_trace):
    sim = ShrewSim(C=p["C"], buffer_ms=p["buffer_ms"], n_flows=p["n_flows"],
                   rtt=p["rtt"], minrto=p["minrto"], R=p["R"], l=p["l"], T=p["T"],
                   dt=p["dt"], duration=p["duration"], benign=p["benign"],
                   recovery=p["recovery"], rto_cap=p["rto_cap"],
                   record_trace=want_trace, pkt_sample=p["pkt_sample"], seed=p["seed"])
    sim.run()

    rho_b = sim.mean_rho("benign")
    rho_a = sim.mean_rho("attack")
    rho_r = sim.mean_rho("recovery")
    avg_rate = p["R"] * p["l"] / p["T"]            # taxa media do atacante (Mb/s)
    row = {"tag": tag, **{k: p[k] for k in ["C", "buffer_ms", "n_flows", "rtt",
           "minrto", "R", "l", "T", "duration"]},
           "avg_atk_rate": round(avg_rate, 3),
           "avg_atk_frac_C": round(avg_rate / p["C"], 4),
           "rho_benign": round(rho_b, 4) if rho_b is not None else "",
           "rho_attack": round(rho_a, 4) if rho_a is not None else "",
           "rho_recovery": round(rho_r, 4) if rho_r is not None else "",
           "rho_eq2": round(eq2(p["T"], p["minrto"]), 4),
           "reducao_pct": round(100 * (1 - rho_a / rho_b), 1) if rho_b else ""}

    if want_trace and sim.pkts:
        t_end = sim.benign + sim.duration + sim.recovery
        conn_open = {i: 0.0 for i in range(sim.n)}
        conn_close = {i: t_end for i in range(sim.n)}
        # marcos das fases do simulador Shrew (rotulagem por fase temporal):
        # baseline [0, benign), ataque [benign, benign+duration), recuperacao depois.
        # A fase de recuperacao recebe rotulo proprio "recovery"; as janelas em fase
        # "off" da onda durante o ataque permanecem rotuladas como "shrew" (o rotulo
        # segue a fase, nao a presenca de pacotes na janela).
        atk_start = sim.benign
        atk_end = sim.benign + sim.duration
        ds = extract_windows(sim.pkts, conn_open, conn_close, legit_log=[],
                             infra_samples=[], t0=0.0, t_end=t_end,
                             window=p["window_seconds"], attack_label="shrew",
                             attack_start=atk_start, attack_end=atk_end,
                             recovery_label="recovery")
        with open(os.path.join(outdir, f"dataset_{tag}.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=FEATURE_ORDER)
            w.writeheader()
            for r in ds:
                w.writerow(r)
    return row, sim


def fig_frequencia(rows, minrto, figdir):
    Ts = sorted(set(float(r["T"]) for r in rows))
    sim_rho, mod_rho = [], []
    for T in Ts:
        rs = [float(r["rho_attack"]) for r in rows if float(r["T"]) == T and r["rho_attack"] != ""]
        sim_rho.append(sum(rs) / len(rs) if rs else np.nan)
        mod_rho.append(eq2(T, minrto))
    fig, ax = plt.subplots(figsize=(7.2, 4.3))
    ax.plot(Ts, mod_rho, "b-", lw=1.6, label="modelo (Eq. 2)")
    ax.plot(Ts, sim_rho, "r--o", ms=4, lw=1.4, label="simulação")
    for j in (1, 2):
        ax.axvline(minrto / j, color="gray", ls=":", lw=1)
    ax.set_xlabel("Período do ataque $T$ (s)")
    ax.set_ylabel("Throughput normalizado")
    ax.set_title(f"Resposta em frequência do Shrew (minRTO = {minrto:g} s)")
    ax.set_ylim(-0.03, 1.05)
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    for e in ("pdf", "png"):
        fig.savefig(os.path.join(figdir, f"shrew_resposta_frequencia.{e}"), bbox_inches="tight")
    plt.close(fig)
    print("  [fig] shrew_resposta_frequencia")


def fig_impacto(sim, tag, figdir):
    ts = np.array(sim.ts)
    rho = np.array(sim.rho)
    w = max(1, int(1.0 / sim.dt))
    rho_s = np.convolve(rho, np.ones(w) / w, mode="same")
    b, d = sim.benign, sim.duration
    fig, ax = plt.subplots(figsize=(7.4, 4))
    ax.plot(ts, rho_s, color=BENIGN_C, lw=1.5, label="throughput (média móvel 1s)")
    ax.axvspan(0, b, color=BENIGN_C, alpha=0.06)
    ax.axvspan(b, b + d, color=ATTACK_C, alpha=0.08)
    ax.axvspan(b + d, ts.max(), color=BENIGN_C, alpha=0.06)
    ax.axvline(b, color="gray", ls="--", lw=1.3)
    ax.axvline(b + d, color="gray", ls="--", lw=1.3)
    ax.set_xlabel("tempo (s)")
    ax.set_ylabel("throughput normalizado")
    ax.set_title(f"Impacto do Shrew no throughput TCP ({tag})")
    ax.set_ylim(-0.03, 1.05)
    ax.grid(alpha=0.3)
    ax.legend(loc="center right")
    fig.tight_layout()
    for e in ("pdf", "png"):
        fig.savefig(os.path.join(figdir, f"shrew_impacto_{tag}.{e}"), bbox_inches="tight")
    plt.close(fig)
    print(f"  [fig] shrew_impacto_{tag}")


DEFAULTS = {"C": 15.0, "buffer_ms": 30.0, "n_flows": 20, "rtt": 0.04, "minrto": 1.0,
            "R": 15.0, "l": 0.24, "T": 1.0, "dt": 0.005, "duration": 60.0,
            "benign": 10.0, "recovery": 15.0, "rto_cap": 4.0, "pkt_sample": 3,
            "window_seconds": 1.0, "seed": 1}


def main():
    ap = argparse.ArgumentParser(description="Simulador Shrew (OFAT + dataset + figuras).")
    ap.add_argument("--outdir", default="shrew_out")
    ap.add_argument("--figdir", default="shrew_out/figuras")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--sweep", default="T", choices=["T", "l", "none"],
                    help="parametro da varredura OFAT")
    ap.add_argument("--reference-tag", default="T1.0",
                    help="cenario para a figura de impacto throughput(t)")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    os.makedirs(args.figdir, exist_ok=True)

    sweeps = {
        "T": [("T", v) for v in [0.4, 0.5, 0.6, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0]],
        "l": [("l", v) for v in [0.03, 0.05, 0.10, 0.15, 0.24]],
        "none": [(None, None)],
    }[args.sweep]

    all_rows = []
    ref_sim = None
    for (param, val) in sweeps:
        for rep in range(args.repeats):
            p = dict(DEFAULTS)
            if param:
                p[param] = val
            p["seed"] = DEFAULTS["seed"] + rep
            tag = (f"{param}{val}" if param else "baseline")
            if args.repeats > 1:
                tag += f"__rep{rep}"
            print(f"[run] {tag}  (T={p['T']} l={p['l']} R={p['R']} C={p['C']} "
                  f"n={p['n_flows']} dur={p['duration']}s)")
            row, sim = run_scenario(p, tag, args.outdir, want_trace=True)
            all_rows.append(row)
            print(f"      -> rho: benigno={row['rho_benign']} ataque={row['rho_attack']} "
                  f"recup={row['rho_recovery']} | reducao={row['reducao_pct']}% "
                  f"| taxa_media={row['avg_atk_rate']} Mb/s ({row['avg_atk_frac_C']} de C)")
            if tag.startswith(args.reference_tag):
                ref_sim = sim

    with open(os.path.join(args.outdir, "results_shrew.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        w.writeheader()
        for r in all_rows:
            w.writerow(r)
    print(f"\nGravado {len(all_rows)} cenario(s) em {args.outdir}/results_shrew.csv")

    if args.sweep == "T":
        fig_frequencia(all_rows, DEFAULTS["minrto"], args.figdir)
    if ref_sim is not None:
        fig_impacto(ref_sim, args.reference_tag, args.figdir)


if __name__ == "__main__":
    main()
