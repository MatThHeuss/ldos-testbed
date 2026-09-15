"""
gera_edos.py — Materializa as colunas da dimensao economica (EDoS) no dataset:
  - containers_N : numero de replicas N(t) por janela, gerado por um auto-scaler
                   simulado (politica de utilizacao com cooldown) aplicado sobre a
                   ocupacao do pool de cada execucao
  - custo        : custo excedente acumulado ate a janela, C_base * integral de
                   (N(t) - N0) dt na FASE DE ATAQUE, com N0 = 1 e dt = 1s (C_base = 1).
                   Zero nas fases benigna e de recuperacao.
  - scaling_induced : 1 nas janelas da fase de ataque em que N(t) > N0, 0 caso contrario

O Shrew nao possui ocupacao de pool (ataque de transporte, sem servidor de aplicacao);
para ele, N(t) = 1, custo = 0 e scaling_induced = 0, pois nao induz provisionamento.

capacity_per_replica = capacidade do servidor de cada ataque (30 Slowloris, 8 LoRDAS),
pois cada replica corresponde a um servidor identico ao do testbed.

Uso:
  python3 gera_edos.py entrada.csv saida.csv
"""
import csv, sys
from collections import defaultdict

CAP_PER_REPLICA = {'slowloris': 30, 'lordas': 8}  # = capacidade do servidor
SCALE_UP, SCALE_DOWN = 0.8, 0.3
COOLDOWN = 1.0
MIN_REP, MAX_REP = 1, 10
C_BASE = 1.0

def f(x):
    try: return float(x)
    except: return None

def autoscale_execucao(exec_rows):
    """Aplica o auto-scaler sobre a ocupacao (httpd_procs) de uma execucao.
    Retorna dict id(row) -> (N, custo_acumulado, scaling_induced)."""
    attack = exec_rows[0]['scenario_attack']
    exec_rows.sort(key=lambda r: f(r['window_start']))

    # Shrew: sem pool -> N=1, custo=0, scaling=0
    if attack == 'shrew':
        return {id(r): (1, 0.0, 0) for r in exec_rows}

    cap = CAP_PER_REPLICA[attack]
    replicas = MIN_REP
    last_change = -1e9
    custo_acc = 0.0
    N0 = MIN_REP
    out = {}
    for r in exec_rows:
        t = f(r['window_start'])
        busy = f(r['httpd_procs'])
        if busy is None:
            out[id(r)] = (replicas, round(custo_acc,4), 0)
            continue
        # politica de utilizacao com cooldown
        util = busy / (cap * replicas) if replicas > 0 else 1.0
        if t - last_change >= COOLDOWN:
            if util > SCALE_UP and replicas < MAX_REP:
                replicas += 1; last_change = t
            elif util < SCALE_DOWN and replicas > MIN_REP:
                replicas -= 1; last_change = t
        # custo excedente acumulado APENAS na fase de ataque (integral de (N-N0)+ dt)
        is_attack_phase = (r['label'] == attack)
        if is_attack_phase:
            custo_acc += C_BASE * max(replicas - N0, 0) * 1.0
        # scaling_induced: 1 se na fase de ataque e N>N0
        scaling = 1 if (is_attack_phase and replicas > N0) else 0
        out[id(r)] = (replicas, round(custo_acc,4), scaling)
    return out

def main():
    inp, out_path = sys.argv[1], sys.argv[2]
    rows = list(csv.DictReader(open(inp)))
    header = list(rows[0].keys())

    execs = defaultdict(list)
    for r in rows:
        execs[(r['scenario_attack'], r['scenario_param'], r['scenario_value'], r['scenario_rep'])].append(r)

    edos = {}
    for key, er in execs.items():
        edos.update(autoscale_execucao(er))

    # containers_N ja existe no header; custo e scaling_induced sao novas
    new_cols = [c for c in ['custo', 'scaling_induced'] if c not in header]
    out_header = header + new_cols

    with open(out_path, 'w', newline='') as fout:
        w = csv.DictWriter(fout, fieldnames=out_header)
        w.writeheader()
        for r in rows:
            N, custo, scaling = edos[id(r)]
            r2 = dict(r)
            r2['containers_N'] = N          # sobrescreve o constante por N(t)
            r2['custo'] = custo
            r2['scaling_induced'] = scaling
            w.writerow(r2)
    print(f"gravado {out_path} com {len(rows)} linhas, {len(out_header)} colunas")

if __name__ == '__main__':
    main()