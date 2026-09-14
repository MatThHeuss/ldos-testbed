"""
relabel_recovery.py — Pos-processa um dataset ja gerado para aplicar a rotulagem de
tres fases (Opcao 1): a fase de recuperacao recebe o rotulo proprio "recovery".

Motivacao: a rotulagem original marcava como "benign" toda janela sem trafego do
atacante, o que rotulava incorretamente a fase de recuperacao (onde o atacante ja
parou, mas o pool pode continuar saturado pelo rescaldo do ataque) como trafego
benigno. Isso contaminava o baseline e criava exemplos rotulados de forma contraditoria
(pool cheio + disponibilidade zero rotulado como "benign").

A correcao usa o marco temporal do fim do ataque (attack_end = benign + attack_dur,
relativo ao inicio de cada execucao). Como cada execucao tem a mesma estrutura de fases
e o dataset registra window_start relativo ao inicio da execucao, a fase de recuperacao
corresponde as janelas com ponto medio >= attack_end.

Nao altera as janelas de ataque nem o baseline verdadeiro; apenas reetiqueta a
recuperacao. As features (inclusive as vazias do Shrew) permanecem intactas.

Uso:
  python docker/relabel_recovery.py \
      --in sweep_full/dataset_ldos_3ataques.csv \
      --out sweep_full/dataset_ldos_3ataques_relabel.csv \
      --benign 15 --attack-dur 40 --window 1.0
"""
import argparse
import csv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--benign", type=float, default=15.0,
                    help="duracao da fase benigna (s)")
    ap.add_argument("--attack-dur", type=float, default=40.0,
                    help="duracao da fase de ataque (s)")
    ap.add_argument("--window", type=float, default=1.0,
                    help="tamanho da janela (s), para o ponto medio")
    ap.add_argument("--recovery-label", default="recovery")
    ap.add_argument("--skip-attacks", default="shrew",
                    help="ataques (scenario_attack) a NAO reetiquetar, separados por virgula. "
                         "O Shrew e simulacao com estrutura propria; por padrao nao e tocado.")
    ap.add_argument("--only-attacks", default="",
                    help="se fornecido, reetiqueta APENAS estes ataques (separados por virgula), "
                         "ignorando --skip-attacks. Util para tratar o Shrew com seus proprios "
                         "marcos de fase (ex.: --only-attacks shrew --benign 10 --attack-dur 60).")
    args = ap.parse_args()

    attack_end = args.benign + args.attack_dur
    skip = set(s.strip() for s in args.skip_attacks.split(",") if s.strip())
    only = set(s.strip() for s in args.only_attacks.split(",") if s.strip())

    n_total = 0
    n_relabel = 0
    n_by_new = {}
    with open(args.inp) as fin:
        reader = csv.DictReader(fin)
        header = reader.fieldnames
        with open(args.out, "w", newline="") as fout:
            w = csv.DictWriter(fout, fieldnames=header)
            w.writeheader()
            for row in reader:
                n_total += 1
                atk = row.get("scenario_attack", "")
                # decide se esta linha deve ser reetiquetada:
                #  - se --only-attacks foi dado: apenas os ataques nessa lista
                #  - caso contrario: todos, menos os de --skip-attacks
                if only:
                    processa = atk in only
                else:
                    processa = atk not in skip
                if processa:
                    try:
                        ws = float(row["window_start"])
                        we = float(row["window_end"])
                        w_mid = (ws + we) / 2.0
                    except (KeyError, ValueError):
                        w_mid = None
                    if w_mid is not None:
                        # rotulagem por FASE TEMPORAL (nao por presenca de pacotes):
                        #  - antes do ataque: benign
                        #  - durante o ataque: <ataque> (mesmo em janelas em que o
                        #    atacante apenas mantem conexoes sem enviar pacotes)
                        #  - depois do ataque: recovery
                        old = row["label"]
                        if w_mid < args.benign:
                            new = "benign"
                        elif w_mid < attack_end:
                            new = atk  # o proprio ataque do cenario (slowloris/lordas)
                        else:
                            new = args.recovery_label
                        if new != old:
                            row["label"] = new
                            n_relabel += 1
                lab = row["label"]
                n_by_new[lab] = n_by_new.get(lab, 0) + 1
                w.writerow(row)

    print(f"[relabel] entrada: {args.inp}")
    print(f"[relabel] attack_end = {attack_end:.0f}s (benign {args.benign:.0f} + ataque {args.attack_dur:.0f})")
    print(f"[relabel] janelas reetiquetadas para '{args.recovery_label}': {n_relabel}")
    print(f"[relabel] total de janelas: {n_total}")
    print(f"[relabel] distribuicao final de rotulos: {dict(sorted(n_by_new.items()))}")
    print(f"[relabel] (ataques nao tocados: {skip})")


if __name__ == "__main__":
    main()
