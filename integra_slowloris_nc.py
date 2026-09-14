"""
integra_slowloris_nc.py — Anexa novos pontos de N_c do Slowloris ao dataset consolidado,
sem tocar nas demais janelas.

Uso:
  python3 integra_slowloris_nc.py \
      --novos sweep_nc/dataset_ldos_3ataques.csv \
      --consolidated dataset_ldos_3ataques_v2.csv \
      --out dataset_ldos_3ataques_v3.csv

O script apenas ACRESCENTA as linhas do arquivo --novos ao final do consolidado,
preservando tudo o que ja existe. Nao remove nada: use-o so para pontos de N_c que
ainda nao estao no consolidado. Ele recusa a operacao se detectar que algum par
(scenario_value, scenario_rep) de n_conns ja existe, para evitar duplicatas.
"""
import argparse
import csv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--novos", required=True,
                    help="consolidado gerado pela varredura dos novos N_c")
    ap.add_argument("--consolidated", required=True, help="dataset vigente")
    ap.add_argument("--out", required=True, help="dataset final")
    args = ap.parse_args()

    with open(args.consolidated) as f:
        header = next(csv.reader(f))

    # pares (valor, rep) de n_conns ja presentes no consolidado
    existentes = set()
    with open(args.consolidated) as f:
        for r in csv.DictReader(f):
            if r.get("scenario_attack") == "slowloris" and r.get("scenario_param") == "n_conns":
                existentes.add((r["scenario_value"], r["scenario_rep"]))

    # le e valida as linhas novas
    with open(args.novos) as f:
        novos_header = next(csv.reader(f))
    faltando = [c for c in novos_header if c not in header]
    if faltando:
        raise SystemExit(f"colunas do arquivo novo ausentes no consolidado: {faltando}")

    novas_linhas = []
    valores_novos = set()
    with open(args.novos) as f:
        for r in csv.DictReader(f):
            if r.get("scenario_attack") != "slowloris" or r.get("scenario_param") != "n_conns":
                raise SystemExit(
                    "o arquivo --novos contem linhas que nao sao slowloris/n_conns; "
                    "gere-o com a varredura restrita a esses pontos.")
            chave = (r["scenario_value"], r["scenario_rep"])
            if chave in existentes:
                raise SystemExit(
                    f"N_c={r['scenario_value']} rep={r['scenario_rep']} ja existe no "
                    f"consolidado. Abortando para nao duplicar.")
            valores_novos.add(r["scenario_value"])
            novas_linhas.append(r)

    # Lê o consolidado inteiro para a memória ANTES de abrir a saída em modo "w",
    # tornando a operação segura mesmo quando --out e --consolidated são o mesmo
    # arquivo (o modo "w" trunca o arquivo ao abrir).
    linhas_orig = []
    with open(args.consolidated) as fin:
        for r in csv.DictReader(fin):
            linhas_orig.append(r)

    with open(args.out, "w", newline="") as fout:
        w = csv.DictWriter(fout, fieldnames=header)
        w.writeheader()
        for r in linhas_orig:
            w.writerow(r)
        for r in novas_linhas:
            w.writerow({c: r.get(c, "") for c in header})

    n_orig = len(linhas_orig)

    print(f"[integra] dataset final: {args.out}")
    print(f"[integra]   linhas originais: {n_orig}")
    print(f"[integra]   novos pontos N_c: {sorted(valores_novos, key=float)}")
    print(f"[integra]   linhas anexadas: {len(novas_linhas)}")
    print(f"[integra]   total: {n_orig + len(novas_linhas)}")


if __name__ == "__main__":
    main()