"""
integra_shrew.py — Integra os datasets do Shrew (simulador) ao dataset consolidado
de LDoS (gerado pela varredura Docker).

O Shrew e um ataque de camada de TRANSPORTE: ele nao interage com o servidor, entao
as features de infraestrutura (cpu_pct, mem_mib, httpd_procs, containers_N) NAO se
aplicam e sao deixadas VAZIAS (N/A honesto). O Shrew e discriminado pelas features
de REDE (rajadas periodicas, entropia, etc.), que sao geradas pelo mesmo features.py
e portanto compativeis coluna a coluna com o dataset Docker.

Cada janela do Shrew recebe as mesmas colunas de rastreabilidade do dataset Docker:
  scenario_attack=shrew, scenario_param=T, scenario_value=<valor de T>, scenario_rep=0

Uso:
  python docker/integra_shrew.py \
      --shrew-dir shrew_out_final \
      --consolidated sweep_full/dataset_ldos_completo.csv \
      --out sweep_full/dataset_ldos_completo_3ataques.csv
"""
import argparse
import csv
import glob
import os
import re

# features de infraestrutura que NAO se aplicam ao Shrew (ficam vazias)
INFRA_FEATURES = ["cpu_pct", "mem_mib", "httpd_procs", "containers_N"]
PROV_COLS = ["scenario_attack", "scenario_param", "scenario_value", "scenario_rep"]


def tag_from_filename(path):
    """Extrai o valor de T do nome do arquivo dataset_T<valor>.csv."""
    m = re.search(r"dataset_T([0-9.]+)\.csv$", os.path.basename(path))
    return m.group(1) if m else os.path.basename(path)


def main():
    ap = argparse.ArgumentParser(description="Integra Shrew ao dataset consolidado LDoS.")
    ap.add_argument("--shrew-dir", required=True,
                    help="pasta com os dataset_T*.csv do Shrew")
    ap.add_argument("--consolidated", required=True,
                    help="dataset consolidado do Docker (com colunas de rastreabilidade)")
    ap.add_argument("--out", required=True, help="dataset final (3 ataques)")
    ap.add_argument("--empty-value", default="",
                    help="valor para as features de infra do Shrew (padrao: vazio)")
    args = ap.parse_args()

    # 1. le o cabecalho do consolidado (define a ordem final das colunas)
    with open(args.consolidated) as f:
        reader = csv.reader(f)
        final_header = next(reader)
    # confere que as colunas de rastreabilidade estao la
    for c in PROV_COLS:
        if c not in final_header:
            raise SystemExit(f"coluna de rastreabilidade ausente no consolidado: {c}")
    feature_cols = [c for c in final_header if c not in PROV_COLS]

    # 2. escreve o dataset final: primeiro copia o consolidado do Docker inteiro
    n_docker = 0
    with open(args.out, "w", newline="") as fout:
        w = csv.DictWriter(fout, fieldnames=final_header)
        w.writeheader()
        with open(args.consolidated) as fin:
            for row in csv.DictReader(fin):
                w.writerow(row)
                n_docker += 1

        # 3. anexa as janelas do Shrew, com infra vazia e rastreabilidade
        shrew_files = sorted(glob.glob(os.path.join(args.shrew_dir, "dataset_T*.csv")))
        if not shrew_files:
            raise SystemExit(f"nenhum dataset_T*.csv encontrado em {args.shrew_dir}")
        n_shrew = 0
        for path in shrew_files:
            t_val = tag_from_filename(path)
            # confere compatibilidade de colunas (features)
            with open(path) as f:
                shrew_header = next(csv.reader(f))
            faltando = [c for c in shrew_header if c not in final_header]
            if faltando:
                raise SystemExit(f"{path}: colunas do Shrew ausentes no consolidado: {faltando}")
            with open(path) as f:
                for row in csv.DictReader(f):
                    out_row = {c: row.get(c, "") for c in feature_cols}
                    for c in INFRA_FEATURES:            # infra NAO se aplica ao Shrew
                        out_row[c] = args.empty_value
                    out_row["scenario_attack"] = "shrew"
                    out_row["scenario_param"] = "T"
                    out_row["scenario_value"] = t_val
                    out_row["scenario_rep"] = 0
                    w.writerow(out_row)
                    n_shrew += 1

    print(f"[integra] dataset final: {args.out}")
    print(f"[integra]   janelas do Docker (slowloris+lordas): {n_docker}")
    print(f"[integra]   janelas do Shrew (infra vazia):       {n_shrew}")
    print(f"[integra]   total: {n_docker + n_shrew}")
    print(f"[integra]   features de infra vazias no Shrew: {INFRA_FEATURES}")


if __name__ == "__main__":
    main()
