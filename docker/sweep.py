"""
sweep.py — Varredura OFAT no Docker, gerando um DATASET CONSOLIDADO de LDoS.

Roda cenarios sequencialmente (um ataque de cada vez, um parametro por vez, N
repeticoes), reaproveitando o run_scenario ja validado do orchestrator.py. Cada
janela recebe colunas de rastreabilidade (ataque, parametro, valor, repeticao). O
dataset consolidado e escrito INCREMENTALMENTE (apos cada cenario), de modo que uma
falha no meio nao perde o trabalho ja feito.

Varreduras (OFAT):
  Slowloris: N_c (cruza MaxRequestWorkers) e delta (cruza t_k)
  LoRDAS:    t_ontime, t_offtime e delta

Uso:
  # validacao barata da mecanica (poucos cenarios, rodadas curtas, ~alguns minutos):
  python docker/sweep.py --minimal --outdir sweep_min

  # varredura completa (rodadas de 40s, 3 repeticoes, ~80 min):
  python docker/sweep.py --outdir sweep_full --repeats 3 --attack-dur 40
"""
import argparse
import csv
import os
import subprocess
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import orchestrator as O

PROV_COLS = ["scenario_attack", "scenario_param", "scenario_value", "scenario_rep"]


def base_params(attack, args):
    """Parametros base de cada ataque (os nao-variados ficam fixos aqui)."""
    p = dict(
        attack=attack,
        benign=args.benign, attack_dur=args.attack_dur, recovery=args.recovery,
        lam=args.lam, legit_src_ips=16,
        service_work=args.service_work, conn_mem_kb=args.conn_mem_kb,
        ts_mean=0.2, window_seconds=1.0,
        # slowloris
        capacity=(30 if attack == "slowloris" else 8),
        n_conns=60, delta=(2.0 if attack == "slowloris" else 0.005), t_k=8.0,
        # lordas
        t_ontime=0.01, t_offtime=0.02,
    )
    return p


# def sweeps(minimal):
#     """Gera tuplas (attack, param, [valores]). Minimal = subconjunto barato."""
#     if minimal:
#         return [
#             ("slowloris", "n_conns", [30, 60]),
#             ("lordas", "delta", [0.005, 0.01]),
#         ]
#     return [
#         # Slowloris
#         ("slowloris", "n_conns", [15, 24, 30, 36, 60]),   # cruza capacidade=30
#         ("slowloris", "delta",   [1.0, 3.0, 6.0, 10.0, 16.0]),  # cruza t_k=8
#         # LoRDAS
#         ("lordas", "t_ontime",  [0.005, 0.01, 0.02, 0.04]),
#         ("lordas", "t_offtime", [0.01, 0.02, 0.04, 0.08]),
#         ("lordas", "delta",     [0.002, 0.005, 0.01, 0.02]),
#     ]


def sweeps(minimal):
    return [
        ("slowloris", "n_conns", [26, 27, 28, 29]),
    ]

def main():
    ap = argparse.ArgumentParser(description="Varredura OFAT Docker -> dataset consolidado.")
    ap.add_argument("--outdir", default="sweep_out")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--minimal", action="store_true",
                    help="poucos cenarios e rodadas curtas, so p/ validar a mecanica")
    ap.add_argument("--benign", type=float, default=15)
    ap.add_argument("--attack-dur", type=float, default=40)
    ap.add_argument("--recovery", type=float, default=10)
    ap.add_argument("--lam", type=float, default=20)
    ap.add_argument("--service-work", type=int, default=200000)
    ap.add_argument("--conn-mem-kb", type=int, default=256)
    args = ap.parse_args()

    if args.minimal:                     # rodadas curtas e 2 repeticoes na validacao
        args.benign, args.attack_dur, args.recovery = 6, 10, 6
        args.repeats = min(args.repeats, 2)

    os.makedirs(args.outdir, exist_ok=True)
    consolidated = os.path.join(args.outdir, "dataset_ldos_completo.csv")
    header_written = False
    fieldnames = None

    plan = sweeps(args.minimal)
    total = sum(len(vals) for (_, _, vals) in plan) * args.repeats
    print(f"[sweep] {total} cenarios no total "
          f"(~{total * (args.benign + args.attack_dur + args.recovery + 20) / 60:.0f} min estimados)")

    done = 0
    t_start = time.time()
    for (attack, param, values) in plan:
        for val in values:
            for rep in range(args.repeats):
                done += 1
                tag = f"{attack}_{param}{val}_rep{rep}"
                elapsed = (time.time() - t_start) / 60
                print(f"\n[sweep] ({done}/{total}) {tag}  decorrido={elapsed:.0f}min")
                p = base_params(attack, args)
                p[param] = val
                p["outdir"] = os.path.join(args.outdir, "runs", tag)
                os.makedirs(p["outdir"], exist_ok=True)
                try:
                    rows = O.run_scenario(p)
                except Exception as e:
                    print(f"[sweep] ERRO no cenario {tag}: {e}")
                    traceback.print_exc()
                    O.cleanup()
                    time.sleep(2)
                    continue

                # anexa rastreabilidade e escreve incrementalmente
                if not header_written:
                    fieldnames = O.FEATURE_ORDER + PROV_COLS
                    with open(consolidated, "w", newline="") as f:
                        csv.DictWriter(f, fieldnames=fieldnames).writeheader()
                    header_written = True
                with open(consolidated, "a", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=fieldnames)
                    for r in rows:
                        r = dict(r)
                        r.update({"scenario_attack": attack, "scenario_param": param,
                                  "scenario_value": val, "scenario_rep": rep})
                        w.writerow(r)
                print(f"[sweep] {tag}: {len(rows)} janelas -> consolidado")

    O.cleanup()
    print(f"\n[sweep] concluido em {(time.time() - t_start)/60:.0f} min.")
    print(f"[sweep] dataset consolidado: {consolidated}")


if __name__ == "__main__":
    main()
