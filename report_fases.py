"""
report_fases.py — Agrega metricas POR FASE (benigno / ataque / recuperacao) a
partir dos arquivos por janela (dataset_*.csv e queue_*.csv), com media +- desvio
sobre as repeticoes. Serve para preencher a tabela da secao (os numeros do
results.csv sao da rodada INTEIRA e misturam as fases).

Uso:
  python report_fases.py --dir oficial --scenario baseline
  python report_fases.py --dir oficial --scenario baseline --drop-edges

Fases (por rotulo + tempo):
  benigno    = janelas 'benign' ANTES da 1a janela de ataque
  ataque     = janelas 'lordas'  (com --drop-edges, descarta a 1a e a ultima,
               que sao de transicao/parciais)
  recuperacao= janelas 'benign' DEPOIS da ultima janela de ataque
"""
import argparse
import csv
import glob
import os
import statistics as st


def _f(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return None


def _load(path):
    with open(path) as fh:
        return list(csv.DictReader(fh))


def _phases(ds_rows, drop_edges):
    labels = [r["label"] for r in ds_rows]
    atk_idx = [i for i, l in enumerate(labels) if l != "benign"]
    if not atk_idx:
        return [], [], []
    a0, a1 = atk_idx[0], atk_idx[-1]
    benign = list(range(0, a0))
    recovery = list(range(a1 + 1, len(ds_rows)))
    attack = list(range(a0, a1 + 1))
    if drop_edges and len(attack) > 2:
        attack = attack[1:-1]      # remove transicao de subida/descida
    return benign, attack, recovery


def _mean_col(rows, idxs, col):
    vals = [_f(rows[i][col]) for i in idxs if _f(rows[i][col]) is not None]
    return st.mean(vals) if vals else None


def _mean_prod(rows, idxs, c1, c2):
    vals = [_f(rows[i][c1]) * _f(rows[i][c2]) for i in idxs
            if _f(rows[i][c1]) is not None and _f(rows[i][c2]) is not None]
    return st.mean(vals) if vals else None


def scenario_stats(dsdir, scenario, drop_edges):
    ds_files = sorted(glob.glob(os.path.join(dsdir, f"dataset_{scenario}__rep*.csv")))
    if not ds_files:
        ds_files = sorted(glob.glob(os.path.join(dsdir, f"dataset_{scenario}.csv")))
    if not ds_files:
        return None

    per_rep = {k: [] for k in
               ["A_ben", "A_atk", "A_rec", "rt_ben", "rt_atk",
                "rec_atk", "occ_ben", "occ_atk", "full_atk",
                "pkt_ben", "pkt_atk", "syn_ben", "syn_atk"]}
    for dsf in ds_files:
        ds = _load(dsf)
        ben, atk, rec = _phases(ds, drop_edges)
        per_rep["A_ben"].append(_mean_col(ds, ben, "availability_A"))
        per_rep["A_atk"].append(_mean_col(ds, atk, "availability_A"))
        per_rep["A_rec"].append(_mean_col(ds, rec, "availability_A"))
        per_rep["rt_ben"].append(_mean_col(ds, ben, "rt_mean"))
        per_rep["rt_atk"].append(_mean_col(ds, atk, "rt_mean"))
        per_rep["rec_atk"].append(_mean_col(ds, atk, "refused_rate"))
        per_rep["pkt_ben"].append(_mean_col(ds, ben, "pkt_count"))
        per_rep["pkt_atk"].append(_mean_col(ds, atk, "pkt_count"))
        per_rep["syn_ben"].append(_mean_prod(ds, ben, "pkt_count", "syn_ratio"))
        per_rep["syn_atk"].append(_mean_prod(ds, atk, "pkt_count", "syn_ratio"))
        # ocupacao: do queue_ correspondente, se existir
        qf = dsf.replace("dataset_", "queue_")
        if os.path.exists(qf):
            q = _load(qf)
            qben, qatk, qrec = _phases_by_time(q, ds, ben, atk, rec)
            per_rep["occ_ben"].append(_mean_col(q, qben, "occ_mean"))
            per_rep["occ_atk"].append(_mean_col(q, qatk, "occ_mean"))
            per_rep["full_atk"].append(_mean_col(q, qatk, "full_fraction"))

    def agg(key):
        vals = [v for v in per_rep[key] if v is not None]
        if not vals:
            return None
        return st.mean(vals), (st.pstdev(vals) if len(vals) > 1 else 0.0), len(vals)

    return {k: agg(k) for k in per_rep}


def _phases_by_time(q, ds, ben, atk, rec):
    # alinha janelas do queue por window_start com as do dataset
    def wins(idxs):
        return {round(_f(ds[i]["window_start"]), 3) for i in idxs}
    ben_t, atk_t, rec_t = wins(ben), wins(atk), wins(rec)
    qb = [i for i, r in enumerate(q) if round(_f(r["window_start"]), 3) in ben_t]
    qa = [i for i, r in enumerate(q) if round(_f(r["window_start"]), 3) in atk_t]
    qr = [i for i, r in enumerate(q) if round(_f(r["window_start"]), 3) in rec_t]
    return qb, qa, qr


def _fmt(a, pct=False, unit=""):
    if a is None:
        return "  (sem dados)"
    m, s, n = a
    if pct:
        return f"{100*m:.1f}% +/- {100*s:.1f}%  (n={n})"
    return f"{m:.4f} +/- {s:.4f}{unit}  (n={n})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="oficial")
    ap.add_argument("--scenario", default="baseline")
    ap.add_argument("--drop-edges", action="store_true",
                    help="descarta a 1a e a ultima janela de ataque (transicao)")
    a = ap.parse_args()
    s = scenario_stats(a.dir, a.scenario, a.drop_edges)
    if s is None:
        print(f"Nenhum dataset_{a.scenario}__rep*.csv em {a.dir}/")
        return
    edge = " (sem janelas de transicao)" if a.drop_edges else ""
    print(f"=== Cenario '{a.scenario}'{edge} — media +/- desvio sobre repeticoes ===\n")
    print(f"Disponibilidade A (benigno)      : {_fmt(s['A_ben'], pct=True)}")
    print(f"Disponibilidade A (ataque)       : {_fmt(s['A_atk'], pct=True)}")
    print(f"Disponibilidade A (recuperacao)  : {_fmt(s['A_rec'], pct=True)}")
    print(f"Taxa de recusa   (ataque)        : {_fmt(s['rec_atk'], pct=True)}")
    print(f"Tempo de resposta (benigno)      : {_fmt(s['rt_ben'], unit=' s')}")
    print(f"Tempo de resposta (ataque)       : {_fmt(s['rt_atk'], unit=' s')}")
    print(f"Ocupacao da fila (benigno)       : {_fmt(s['occ_ben'])}")
    print(f"Ocupacao da fila (ataque)        : {_fmt(s['occ_atk'])}")
    print(f"Fracao de tempo com fila cheia   : {_fmt(s['full_atk'])}")
    print(f"Taxa de pacotes (benigno)        : {_fmt(s['pkt_ben'], unit=' pkt/s')}")
    print(f"Taxa de pacotes (ataque)         : {_fmt(s['pkt_atk'], unit=' pkt/s')}")
    print(f"Taxa de SYN (benigno)            : {_fmt(s['syn_ben'], unit=' SYN/s')}")
    print(f"Taxa de SYN (ataque)             : {_fmt(s['syn_atk'], unit=' SYN/s')}")


if __name__ == "__main__":
    main()
