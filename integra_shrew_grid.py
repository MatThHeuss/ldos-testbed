"""
integra_shrew_grid.py — Substitui as janelas do Shrew no dataset consolidado pelas
janelas da nova malha (D, T).

Diferencas em relacao ao integra_shrew.py original:
  - reconhece o novo padrao de nome: dataset_D<d>__T<t>__l<l>.csv
  - registra os dois eixos da malha em scenario_param / scenario_value
  - REMOVE do consolidado as linhas antigas de scenario_attack=shrew antes de anexar
    as novas, de modo que o script pode ser aplicado sobre o dataset final vigente

As features de infraestrutura continuam vazias para o Shrew (N/A honesto), pois o
ataque e de camada de transporte e nao interage com o servidor de aplicacao.

Uso:
  python3 integra_shrew_grid.py \
      --shrew-dir shrew_grid \
      --consolidated dataset_ldos_3ataques_final.csv \
      --out dataset_ldos_3ataques_v2.csv
"""
import argparse
import csv
import glob
import os
import re

INFRA_FEATURES = ["cpu_pct", "mem_mib", "httpd_procs", "containers_N"]
PROV_COLS = ["scenario_attack", "scenario_param", "scenario_value", "scenario_rep"]

# dataset_D0.05__T0.3__l0.015.csv  ->  ("0.05", "0.3", "0.015")
TAG_RE = re.compile(r"dataset_D([0-9.]+)__T([0-9.]+)__l([0-9.]+)\.csv$")


def parse_tag(path):
    m = TAG_RE.search(os.path.basename(path))
    if not m:
        return None
    return {"D": m.group(1), "T": m.group(2), "l": m.group(3)}


def main():
    ap = argparse.ArgumentParser(
        description="Integra a malha (D,T) do Shrew ao dataset consolidado LDoS.")
    ap.add_argument("--shrew-dir", required=True,
                    help="pasta com os dataset_D*__T*__l*.csv do Shrew")
    ap.add_argument("--consolidated", required=True,
                    help="dataset consolidado vigente (as linhas antigas de shrew sao descartadas)")
    ap.add_argument("--out", required=True, help="dataset final")
    ap.add_argument("--empty-value", default="",
                    help="valor para as features de infra do Shrew (padrao: vazio)")
    args = ap.parse_args()

    with open(args.consolidated) as f:
        final_header = next(csv.reader(f))
    for c in PROV_COLS:
        if c not in final_header:
            raise SystemExit(f"coluna de rastreabilidade ausente no consolidado: {c}")
    feature_cols = [c for c in final_header if c not in PROV_COLS]

    shrew_files = sorted(glob.glob(os.path.join(args.shrew_dir, "dataset_D*__T*__l*.csv")))
    if not shrew_files:
        raise SystemExit(
            f"nenhum dataset_D*__T*__l*.csv encontrado em {args.shrew_dir}.\n"
            f"Confira se a varredura foi rodada com --sweep grid.")

    n_keep = 0
    n_drop = 0
    n_shrew = 0

    # Lê o consolidado inteiro para a memória ANTES de abrir a saída em modo "w".
    # Isso torna a operação segura mesmo quando --out e --consolidated apontam para
    # o mesmo arquivo (o modo "w" trunca o arquivo ao abrir, o que apagaria a
    # entrada se ela ainda não tivesse sido lida).
    linhas_mantidas = []
    with open(args.consolidated) as fin:
        for row in csv.DictReader(fin):
            if row.get("scenario_attack") == "shrew":
                n_drop += 1
                continue
            linhas_mantidas.append(row)
            n_keep += 1

    with open(args.out, "w", newline="") as fout:
        w = csv.DictWriter(fout, fieldnames=final_header)
        w.writeheader()

        # 1. escreve as janelas de aplicação preservadas do consolidado
        for row in linhas_mantidas:
            w.writerow(row)

        # 2. anexa as janelas da malha nova
        for path in shrew_files:
            tag = parse_tag(path)
            if tag is None:
                print(f"[aviso] nome fora do padrao, ignorado: {path}")
                continue
            with open(path) as f:
                shrew_header = next(csv.reader(f))
            faltando = [c for c in shrew_header if c not in final_header]
            if faltando:
                raise SystemExit(f"{path}: colunas ausentes no consolidado: {faltando}")
            with open(path) as f:
                for row in csv.DictReader(f):
                    out_row = {c: row.get(c, "") for c in feature_cols}
                    for c in INFRA_FEATURES:
                        out_row[c] = args.empty_value
                    out_row["scenario_attack"] = "shrew"
                    out_row["scenario_param"] = "D_T"
                    out_row["scenario_value"] = f"{tag['D']}__{tag['T']}"
                    out_row["scenario_rep"] = 0
                    w.writerow(out_row)
                    n_shrew += 1

    print(f"[integra] dataset final: {args.out}")
    print(f"[integra]   janelas mantidas (slowloris+lordas): {n_keep}")
    print(f"[integra]   janelas antigas do Shrew descartadas: {n_drop}")
    print(f"[integra]   janelas novas do Shrew ({len(shrew_files)} cenarios): {n_shrew}")
    print(f"[integra]   total: {n_keep + n_shrew}")
    print(f"[integra]   features de infra vazias no Shrew: {INFRA_FEATURES}")


if __name__ == "__main__":
    main()