"""
plots.py — Geracao de graficos a partir dos DADOS das rodadas (fiel aos CSVs).

Le results.csv (varredura), dataset_<tag>.csv (features por janela) e
packets_<tag>.csv (eventos brutos) e produz figuras proprias para uma defesa
de mestrado sobre o ataque LoRDAS. Salva cada figura em PDF (vetorial, p/ LaTeX)
e PNG (conferencia).

Uso:
  python plots.py --results-dir results --figdir figuras [--tag <tag>]

Nenhum dado e inventado: tudo vem dos CSVs gerados por run_experiment.py.
"""
import argparse
import csv
import glob
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ---------------------------------------------------------------- estilo
BENIGN_C = "#2c7fb8"   # azul
ATTACK_C = "#d7301f"   # vermelho
ACCENT_C = "#238b45"   # verde
NEUTRAL = "#555555"

PARAM_LABELS = {
    "t_ontime": r"$t_{ontime}$ (s)", "delta": r"$\Delta$ (s)", "ts_var": r"Var($T_s$)",
    "ts_mean": r"$T_s$ (s)", "n_workers": r"$N_s$", "queue_size": "tamanho da fila",
    "rtt_mean": "RTT médio (s)", "lam": r"$\lambda$ (req/s)", "t_offtime": r"$t_{offtime}$ (s)",
}
SWEEP_CANDIDATES = ["t_ontime", "delta", "ts_var", "ts_mean", "n_workers",
                    "queue_size", "rtt_mean", "lam", "t_offtime"]


def _style():
    plt.rcParams.update({
        "figure.dpi": 120, "savefig.dpi": 150, "font.size": 11,
        "axes.titlesize": 12, "axes.labelsize": 11, "legend.fontsize": 9.5,
        "axes.grid": True, "grid.alpha": 0.3, "grid.linewidth": 0.6,
        "axes.spines.top": False, "axes.spines.right": False,
        "figure.autolayout": False,
    })


def _save(fig, figdir, name):
    os.makedirs(figdir, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(figdir, f"{name}.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print(f"  [fig] {name}.pdf / .png")


def _f(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return np.nan


def _load_csv(path):
    with open(path) as fh:
        return list(csv.DictReader(fh))


def _load_datasets(results_dir):
    """Concatena todos os dataset_*.csv (colunas -> listas) para os plots de distribuicao."""
    files = sorted(glob.glob(os.path.join(results_dir, "dataset_*.csv")))
    cols = {}
    for path in files:
        for row in _load_csv(path):
            for k, v in row.items():
                cols.setdefault(k, []).append(v)
    return cols, files


def _load_params(results_dir):
    """tag -> dict de parametros do cenario (de results.csv), p/ escolha e zoom."""
    path = os.path.join(results_dir, "results.csv")
    params = {}
    if os.path.exists(path):
        for r in _load_csv(path):
            params[r.get("tag", "")] = r
    return params


# ======================================================= 1) SENSIBILIDADE (results.csv)
def _detect_sweep(rows):
    swept = []
    for p in SWEEP_CANDIDATES:
        if p in rows[0]:
            vals = {r[p] for r in rows}
            if len(vals) > 1:
                swept.append(p)
    return swept


def _agg_by(rows, param, ycol):
    """Agrupa por valor do parametro; retorna (xs, means, stds) ordenado por x."""
    buckets = {}
    for r in rows:
        x = _f(r[param])
        y = _f(r.get(ycol, ""))
        if not np.isnan(x) and not np.isnan(y):
            buckets.setdefault(x, []).append(y)
    xs = sorted(buckets)
    means = [float(np.mean(buckets[x])) for x in xs]
    stds = [float(np.std(buckets[x])) for x in xs]
    return np.array(xs), np.array(means), np.array(stds)


def _baseline_values(rows, swept):
    """Valores de baseline por parametro: da linha com tag 'baseline' ou, na
    falta dela, do valor mais frequente (modo) de cada parametro."""
    for r in rows:
        if str(r.get("tag", "")).startswith("baseline"):
            return {p: _f(r[p]) for p in swept}
    base = {}
    for p in swept:
        vals = [_f(r[p]) for r in rows]
        base[p] = max(set(vals), key=vals.count)
    return base


def _row_group(r, swept, baseline):
    if str(r.get("tag", "")).startswith("baseline"):
        return "baseline"
    diffs = [p for p in swept if _f(r[p]) != baseline[p]]
    return diffs[0] if len(diffs) == 1 else "multi"


def _sensibilidade_panel(subset, param, figdir):
    xlab = PARAM_LABELS.get(param, param)
    xC, mC, sC = _agg_by(subset, param, "C")
    xA, mA, sA = _agg_by(subset, param, "A")
    xO, mO, sO = _agg_by(subset, param, "O_eq31_count")
    if xC.size == 0 and xA.size == 0:
        return

    fig, ax1 = plt.subplots(figsize=(7.2, 4.4))
    l1 = ax1.errorbar(xC, mC, yerr=sC, marker="o", color=BENIGN_C, capsize=3,
                      lw=1.8, label=r"$C$ (prob. sucesso do cliente)")
    l2 = ax1.errorbar(xA, mA, yerr=sA, marker="s", color=ATTACK_C, capsize=3,
                      lw=1.8, label=r"$A$ (disponibilidade)")
    ax1.set_xlabel(xlab)
    ax1.set_ylabel(r"$C$, $A$ (fração)")
    ax1.set_ylim(-0.03, 1.03)

    ax2 = ax1.twinx()
    ax2.spines["right"].set_visible(True)
    l3 = ax2.errorbar(xO, mO, yerr=sO, marker="^", color=ACCENT_C, capsize=3,
                      lw=1.8, ls="--", label=r"$O$ (overhead, Eq. 31)")
    ax2.set_ylabel(r"$O$ = $\lfloor t_{on}/\Delta \rfloor + 1 + (1-P_u)$")
    ax2.grid(False)

    lines = [l1, l2, l3]
    ax1.legend(lines, [l.get_label() for l in lines], loc="center left", framealpha=0.9)
    ax1.set_title(f"Sensibilidade dos indicadores a {xlab}")
    fig.text(0.5, -0.02, "Reprodução empírica do estudo de sensibilidade "
             "(Maciá-Fernández et al., 2009, Fig. 9)", ha="center", fontsize=8.5,
             color=NEUTRAL)
    _save(fig, figdir, f"01_sensibilidade_{param}")


def _tradeoff_panel(rows, swept, baseline, figdir):
    """Dispersao A x O de TODOS os cenarios de ataque, agrupada pelo parametro
    que variou (assinatura low-rate: alto impacto com baixo overhead)."""
    groups = {}
    for r in rows:
        A = _f(r.get("A", ""))
        O = _f(r.get("O_eq31_count", ""))
        if np.isnan(A) or np.isnan(O):
            continue
        g = _row_group(r, swept, baseline)
        groups.setdefault(g, ([], []))
        groups[g][0].append(O)
        groups[g][1].append(A)
    if not groups:
        return
    palette = [BENIGN_C, ATTACK_C, ACCENT_C, "#6a51a3", "#e6550d", NEUTRAL]
    markers = ["o", "^", "s", "D", "v", "P"]
    fig, ax = plt.subplots(figsize=(6.6, 4.6))
    for i, (g, (xs, ys)) in enumerate(sorted(groups.items())):
        lbl = "baseline" if g == "baseline" else PARAM_LABELS.get(g, g)
        ax.scatter(xs, ys, c=palette[i % len(palette)], marker=markers[i % len(markers)],
                   s=70, alpha=0.8, edgecolor="k", lw=0.4, label=f"varia {lbl}" if g != "baseline" else lbl)
    ax.set_xlabel(r"$O$ (overhead do atacante, Eq. 31)")
    ax.set_ylabel(r"$A$ (disponibilidade)")
    ax.set_ylim(-0.03, 1.03)
    ax.set_title("Assinatura low-rate: alto impacto (baixo $A$) com baixo $O$")
    ax.legend(framealpha=0.9, fontsize=8.5)
    _save(fig, figdir, "02_tradeoff_A_O")


def fig_sensibilidade(rows, figdir):
    swept = _detect_sweep(rows)
    if not swept:
        print("  (sem varredura em results.csv -> pulando sensibilidade e trade-off)")
        return False
    baseline = _baseline_values(rows, swept)
    multi = len(swept) > 1
    for param in swept:
        if multi:
            subset = [r for r in rows
                      if all(_f(r[j]) == baseline[j] for j in swept if j != param)]
        else:
            subset = rows
        _sensibilidade_panel(subset, param, figdir)
    _tradeoff_panel(rows, swept, baseline, figdir)
    return True


# ======================================================= 2) MECANICA (packets_<tag>.csv)
def _pkt_arrays(rows):
    t = np.array([_f(r["time"]) for r in rows])
    tag = np.array([r["tag"] for r in rows])
    kind = np.array([r["kind"] for r in rows])
    direction = np.array([r["direction"] for r in rows])
    return t, tag, kind, direction


def fig_waveform(pkt_rows, figdir, tag_name, period=None, delta=None):
    t, tag, kind, direction = _pkt_arrays(pkt_rows)
    t0 = t.min()
    tt = t - t0
    # chegadas de conexao do atacante (1 SYN por conexao)
    atk = (tag == "attacker") & (direction == "in") & (kind == "syn")
    leg = (tag == "legit") & (direction == "in") & (kind == "syn")
    ta = np.sort(tt[atk])
    tl = np.sort(tt[leg])
    if ta.size < 5:
        print("  (poucos pacotes de ataque -> pulando waveform)")
        return

    dur = tt.max()
    fig, (axtop, axbot) = plt.subplots(2, 1, figsize=(7.6, 5.6))

    # painel superior: taxa (pacotes/s) em bins largos, ataque vs legitimo
    binw = max(dur / 300.0, 0.05)
    edges = np.arange(0, dur + binw, binw)
    ha, _ = np.histogram(ta, bins=edges)
    hl, _ = np.histogram(tl, bins=edges)
    ctr = edges[:-1] + binw / 2
    axtop.plot(ctr, ha / binw, color=ATTACK_C, lw=1.2, label="atacante")
    axtop.plot(ctr, hl / binw, color=BENIGN_C, lw=1.2, label="legítimo")
    axtop.set_xlabel("tempo (s)")
    axtop.set_ylabel("taxa de conexões (1/s)")
    axtop.set_title(f"Forma de onda do LoRDAS ao longo do experimento  ({tag_name})")
    axtop.legend(loc="upper right", framealpha=0.9)

    # painel inferior: zoom no regime estavel, largura/bin derivados do periodo
    per = period if (period and period > 0) else max(float(np.median(np.diff(ta))), 0.004)
    zbw = delta if (delta and delta > 0) else max(per / 4.0, 0.001)
    zwidth = min(max(12 * per, 0.12), 0.5)
    # ancorar o zoom na REGIAO DENSA de ataque (evita cair na calibracao/fase benigna,
    # que inflam o intervalo temporal e deixariam o zoom num trecho silencioso)
    z0 = float(np.percentile(ta, 60))
    if z0 + zwidth > ta[-1]:
        z0 = max(ta[0], ta[-1] - zwidth)
    z1 = z0 + zwidth
    zedges = np.arange(z0, z1 + zbw, zbw)
    hz, _ = np.histogram(ta[(ta >= z0) & (ta <= z1)], bins=zedges)
    axbot.bar(zedges[:-1] - z0, hz, width=zbw * 0.9, align="edge", color=ATTACK_C)
    axbot.set_xlabel("tempo dentro da janela de zoom (s)")
    axbot.set_ylabel("pacotes/bin")
    axbot.set_title(r"Zoom: rajadas ON-OFF (fase ativa a cada $\Delta$, seguida de silêncio)")
    fig.tight_layout()
    _save(fig, figdir, f"03_waveform_{tag_name}")


def fig_iat(pkt_rows, figdir, tag_name):
    t, tag, kind, direction = _pkt_arrays(pkt_rows)
    atk = (tag == "attacker") & (direction == "in") & (kind == "syn")
    leg = (tag == "legit") & (direction == "in") & (kind == "syn")
    ta = np.sort(t[atk])
    tl = np.sort(t[leg])
    ia = np.diff(ta)
    il = np.diff(tl)
    ia = ia[ia > 0]
    il = il[il > 0]
    if ia.size < 10:
        print("  (poucos IAT de ataque -> pulando histograma IAT)")
        return

    fig, ax = plt.subplots(figsize=(7.0, 4.4))
    lo = max(min(ia.min(), il.min() if il.size else ia.min()), 1e-5)
    hi = max(ia.max(), il.max() if il.size else ia.max())
    bins = np.logspace(np.log10(lo), np.log10(hi), 50)
    ax.hist(ia, bins=bins, color=ATTACK_C, alpha=0.65, density=True,
            label="atacante (LoRDAS)")
    if il.size:
        ax.hist(il, bins=bins, color=BENIGN_C, alpha=0.55, density=True,
                label="legítimo (Poisson)")
    ax.set_xscale("log")
    ax.set_xlabel("inter-arrival time entre conexões (s, escala log)")
    ax.set_ylabel("densidade")
    ax.set_title("Distribuição do inter-arrival: LoRDAS é bimodal (intra-rajada vs. silêncio)")
    ax.legend(framealpha=0.9)
    _save(fig, figdir, f"04_iat_hist_{tag_name}")


# ======================================================= 3) IMPACTO TEMPORAL (dataset_<tag>.csv)
def _onset(ds_rows):
    for r in ds_rows:
        if r["label"] != "benign":
            return _f(r["window_start"])
    return None


def fig_impacto_temporal(ds_rows, figdir, tag_name):
    x = np.array([_f(r["window_start"]) for r in ds_rows])
    A = np.array([_f(r["availability_A"]) for r in ds_rows])
    refr = np.array([_f(r["refused_rate"]) for r in ds_rows])
    onset = _onset(ds_rows)

    # detectar fim do ataque (primeira janela benigna apos o inicio) -> 3 fases
    labels = [r["label"] for r in ds_rows]
    attack_end = None
    if onset is not None:
        seen_attack = False
        for xi, lab in zip(x, labels):
            if lab != "benign":
                seen_attack = True
            elif seen_attack:
                attack_end = xi
                break

    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    ax.plot(x, A, marker="o", ms=4, color=BENIGN_C, lw=1.8, label=r"$A(t)$ disponibilidade")
    ax.plot(x, refr, marker="s", ms=4, color=ATTACK_C, lw=1.8, label="taxa de recusa")
    if onset is not None:
        atk_hi = attack_end if attack_end is not None else x.max()
        ax.axvspan(x.min(), onset, color=BENIGN_C, alpha=0.06)
        ax.axvspan(onset, atk_hi, color=ATTACK_C, alpha=0.08)
        if attack_end is not None:
            ax.axvspan(atk_hi, x.max(), color=BENIGN_C, alpha=0.06)
        ax.axvline(onset, color=NEUTRAL, ls="--", lw=1.4)
        ax.annotate("início do ataque", xy=(onset, 0.5), xytext=(onset + 0.4, 0.55),
                    fontsize=9, color=NEUTRAL,
                    arrowprops=dict(arrowstyle="->", color=NEUTRAL))
        if attack_end is not None:
            ax.axvline(atk_hi, color=NEUTRAL, ls="--", lw=1.4)
            ax.annotate("fim do ataque", xy=(atk_hi, 0.5), xytext=(atk_hi + 0.4, 0.4),
                        fontsize=9, color=NEUTRAL,
                        arrowprops=dict(arrowstyle="->", color=NEUTRAL))
    ax.set_xlabel("tempo (s)")
    ax.set_ylabel("fração")
    ax.set_ylim(-0.03, 1.03)
    ax.set_title(f"Impacto do LoRDAS na disponibilidade ao longo do tempo  ({tag_name})")
    ax.legend(loc="center left", framealpha=0.9)
    _save(fig, figdir, f"05_impacto_temporal_{tag_name}")


def fig_edos_infra(ds_rows, figdir, tag_name):
    x = np.array([_f(r["window_start"]) for r in ds_rows])
    cpu = np.array([_f(r["cpu_pct"]) for r in ds_rows])
    httpd = np.array([_f(r["httpd_procs"]) for r in ds_rows])
    cont = np.array([_f(r["containers_N"]) for r in ds_rows])
    onset = _onset(ds_rows)

    fig, ax1 = plt.subplots(figsize=(7.4, 4.2))
    l1, = ax1.plot(x, cont, marker="D", ms=4, color=ACCENT_C, lw=1.8,
                   label=r"$N(t)$ contêineres (auto-scaling)")
    l2, = ax1.plot(x, httpd, marker="^", ms=4, color=NEUTRAL, lw=1.5,
                   label="processos httpd (workers ocupados)")
    ax1.set_xlabel("tempo (s)")
    ax1.set_ylabel("contagem")
    ax2 = ax1.twinx()
    ax2.spines["right"].set_visible(True)
    l3, = ax2.plot(x, cpu, marker="o", ms=4, color=ATTACK_C, lw=1.5, ls="--",
                   label="uso de CPU (%)")
    ax2.set_ylabel("CPU (%)")
    ax2.grid(False)
    if onset is not None:
        ax1.axvline(onset, color=NEUTRAL, ls="--", lw=1.4)
    ax1.legend([l1, l2, l3], [l.get_label() for l in (l1, l2, l3)],
               loc="upper left", framealpha=0.9)
    ax1.set_title(f"EDoS: escalonamento de recursos sob ataque  ({tag_name})")
    _save(fig, figdir, f"06_edos_infra_{tag_name}")


def fig_ocupacao_fila(q_rows, capacity, figdir, tag_name, onset=None):
    """Ocupacao da fila ao longo do tempo (saturando na capacidade) + recusas."""
    x = np.array([_f(r["window_start"]) for r in q_rows])
    occm = np.array([_f(r["occ_mean"]) for r in q_rows])
    occp = np.array([_f(r["occ_peak"]) for r in q_rows])
    ref = np.array([_f(r["refused"]) for r in q_rows])
    if capacity is None or np.isnan(capacity):
        capacity = float(np.nanmax(occp)) if occp.size else 1.0

    fig, ax1 = plt.subplots(figsize=(7.4, 4.3))
    ax1.fill_between(x, occm, color=BENIGN_C, alpha=0.22)
    ax1.plot(x, occm, color=BENIGN_C, lw=1.9, marker="o", ms=3.5, label="ocupação média")
    ax1.plot(x, occp, color=NEUTRAL, lw=1.0, ls=":", label="ocupação de pico")
    ax1.axhline(capacity, color=ATTACK_C, ls="--", lw=1.3)
    ax1.text(x.max(), capacity, " capacidade (fila cheia)", va="bottom", ha="right",
             color=ATTACK_C, fontsize=9)
    ax1.set_ylim(0, capacity * 1.18)
    ax1.set_xlabel("tempo (s)")
    ax1.set_ylabel("posições ocupadas")

    ax2 = ax1.twinx()
    ax2.spines["right"].set_visible(True)
    bw = (x[1] - x[0]) * 0.6 if x.size > 1 else 0.6
    ax2.bar(x, ref, width=bw, color=ATTACK_C, alpha=0.35, label="recusas (fila cheia)")
    ax2.set_ylabel("recusas por janela")
    ax2.grid(False)
    if onset is not None:
        ax1.axvline(onset, color=NEUTRAL, ls="--", lw=1.2)

    h1, l1 = ax1.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax1.legend(h1 + h2, l1 + l2, loc="center left", framealpha=0.9)
    ax1.set_title(f"Ocupação da fila de serviço e recusas  ({tag_name})")
    _save(fig, figdir, f"10_ocupacao_fila_{tag_name}")


# ======================================================= 4) SEPARABILIDADE (todos datasets)
def _grouped(cols, feature):
    vals = np.array([_f(v) for v in cols.get(feature, [])])
    labs = np.array(cols.get("label", []))
    b = vals[(labs == "benign") & ~np.isnan(vals)]
    a = vals[(labs != "benign") & ~np.isnan(vals)]
    return b, a


def fig_separabilidade(cols, figdir):
    feats = [
        ("src_ip_entropy", "entropia de IPs de origem", False),
        ("pkt_count", "nº de pacotes", False),
        ("iat_mean", "inter-arrival médio (s)", True),
        ("active_conns_mean", "conexões ativas (média)", False),
        ("availability_A", "disponibilidade $A$", False),
        ("refused_rate", "taxa de recusa", False),
    ]
    fig, axes = plt.subplots(2, 3, figsize=(11, 6.4))
    for ax, (feat, label, logy) in zip(axes.ravel(), feats):
        b, a = _grouped(cols, feat)
        if b.size == 0 and a.size == 0:
            ax.set_visible(False)
            continue
        data = [b if b.size else np.array([np.nan]), a if a.size else np.array([np.nan])]
        bp = ax.boxplot(data, patch_artist=True, widths=0.6, showfliers=False,
                        medianprops=dict(color="black"))
        for patch, c in zip(bp["boxes"], (BENIGN_C, ATTACK_C)):
            patch.set_facecolor(c)
            patch.set_alpha(0.65)
        ax.set_xticklabels(["benign", "lordas"])
        if logy and (a.size and np.nanmin(np.concatenate([b, a])) > 0):
            ax.set_yscale("log")
        ax.set_title(label)
        ax.grid(axis="x")
    fig.suptitle("Separabilidade das features por classe (benign vs. LoRDAS)", y=1.0)
    fig.tight_layout()
    _save(fig, figdir, "07_separabilidade_features")


def fig_scatter(cols, figdir):
    fx, fy = "src_ip_entropy", "pkt_count"
    x = np.array([_f(v) for v in cols.get(fx, [])])
    y = np.array([_f(v) for v in cols.get(fy, [])])
    labs = np.array(cols.get("label", []))
    m = ~np.isnan(x) & ~np.isnan(y)
    x, y, labs = x[m], y[m], labs[m]
    if x.size == 0:
        return
    fig, ax = plt.subplots(figsize=(6.8, 4.8))
    for lab, c, mk in (("benign", BENIGN_C, "o"), ("lordas", ATTACK_C, "^")):
        sel = labs == lab if lab == "benign" else labs != "benign"
        ax.scatter(x[sel], y[sel], c=c, marker=mk, s=45, alpha=0.75,
                   edgecolor="k", lw=0.4, label=lab)
    ax.set_xlabel("entropia de IPs de origem")
    ax.set_ylabel("nº de pacotes por janela")
    ax.set_yscale("log")
    ax.set_title("Duas features discriminativas separam as classes")
    ax.legend(framealpha=0.9)
    _save(fig, figdir, "08_scatter_features")


def fig_correlacao(cols, figdir):
    feats = ["pkt_count", "byte_count", "active_conns_mean", "src_ip_entropy",
             "src_port_entropy", "distinct_src_ports", "iat_mean", "iat_var",
             "conn_duration_mean", "pkt_size_mean", "cpu_pct", "httpd_procs",
             "availability_A", "refused_rate", "containers_N"]
    feats = [f for f in feats if f in cols]
    mat = []
    for f in feats:
        mat.append([_f(v) for v in cols[f]])
    M = np.array(mat, dtype=float)
    # remove colunas (janelas) com NaN em qualquer feature
    ok = ~np.isnan(M).any(axis=0)
    M = M[:, ok]
    if M.shape[1] < 3:
        print("  (dados insuficientes p/ correlacao)")
        return
    C = np.corrcoef(M)
    fig, ax = plt.subplots(figsize=(8.2, 7))
    im = ax.imshow(C, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(feats)))
    ax.set_yticks(range(len(feats)))
    ax.set_xticklabels(feats, rotation=90, fontsize=8)
    ax.set_yticklabels(feats, fontsize=8)
    for i in range(len(feats)):
        for j in range(len(feats)):
            ax.text(j, i, f"{C[i, j]:.1f}", ha="center", va="center",
                    fontsize=6.5, color="black" if abs(C[i, j]) < 0.6 else "white")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="correlação de Pearson")
    ax.set_title("Correlação entre features (todas as janelas)")
    fig.tight_layout()
    _save(fig, figdir, "09_correlacao_features")


# ======================================================= seleção de cenário
def _pick_scenario(results_dir, tag, params):
    """Escolhe um cenario que mostre bem a estrutura ON-OFF.

    Prefere burst multi-pacote com gap positivo (t_ontime < tau=T_s/N_s):
    score = nº de pacotes por rajada quando ha silencio entre rajadas; caso
    nenhum tenha, cai para o cenario com mais pacotes de ataque.
    """
    ds_files = sorted(glob.glob(os.path.join(results_dir, "dataset_*.csv")))
    if tag:
        cand = os.path.join(results_dir, f"dataset_{tag}.csv")
        if os.path.exists(cand):
            ds_files = [cand]

    best = None
    best_key = (-1, -1e9)   # (tem_gap_e_burst>=2, score)
    for path in ds_files:
        rows = _load_csv(path)
        n_atk = sum(1 for r in rows if r["label"] != "benign")
        if n_atk == 0:
            continue
        base = os.path.basename(path)
        tg = base[len("dataset_"):-len(".csv")]
        atk_pkts = sum(_f(r.get("attacker_pkts", 0)) for r in rows)
        p = params.get(tg)
        if p:
            delta = _f(p.get("delta"))
            t_on = _f(p.get("t_ontime"))
            tau = _f(p.get("ts_mean")) / max(_f(p.get("n_workers")), 1)
            burst = int(t_on / delta) + 1 if delta > 0 else 1
            gap = tau - t_on
            clean = 1 if (gap > 0 and burst >= 2) else 0
            score = burst if clean else atk_pkts / 1e4
            key = (clean, score)
        else:
            key = (0, atk_pkts / 1e4)
        if key > best_key:
            best_key, best = key, (rows, tg)
    if best is None:
        return None, None
    return best


def generate_all(results_dir="results", figdir="figuras", tag=None):
    """Gera todas as figuras a partir dos CSVs em results_dir. Reutilizavel
    pelo run_experiment.py (flag --plots) ou via CLI."""
    _style()
    rdir = results_dir
    args_figdir = figdir
    args_tag = tag
    print(f"Lendo CSVs de {rdir}/ ; salvando figuras em {args_figdir}/")

    # 1) sensibilidade + trade-off (results.csv)
    res_path = os.path.join(rdir, "results.csv")
    if os.path.exists(res_path):
        rows = _load_csv(res_path)
        if rows:
            fig_sensibilidade(rows, args_figdir)

    # cenario representativo p/ figuras temporais e de mecanica
    params = _load_params(rdir)
    ds_rows, tag_name = _pick_scenario(rdir, args_tag, params)
    if ds_rows:
        onset = _onset(ds_rows)
        fig_impacto_temporal(ds_rows, args_figdir, tag_name)
        fig_edos_infra(ds_rows, args_figdir, tag_name)
        q_path = os.path.join(rdir, f"queue_{tag_name}.csv")
        if os.path.exists(q_path):
            cap = _f(params.get(tag_name, {}).get("queue_size")) if params else None
            fig_ocupacao_fila(_load_csv(q_path), cap, args_figdir, tag_name, onset)
        pkt_path = os.path.join(rdir, f"packets_{tag_name}.csv")
        if os.path.exists(pkt_path):
            pkt_rows = _load_csv(pkt_path)
            p = params.get(tag_name, {})
            per = (_f(p.get("ts_mean")) / max(_f(p.get("n_workers")), 1)) if p else None
            dlt = _f(p.get("delta")) if p else None
            fig_waveform(pkt_rows, args_figdir, tag_name, period=per, delta=dlt)
            fig_iat(pkt_rows, args_figdir, tag_name)
        else:
            print(f"  (sem {pkt_path} -> pulando waveform/IAT)")

    # 4) separabilidade + scatter + correlacao (todos os datasets)
    cols, files = _load_datasets(rdir)
    if files:
        fig_separabilidade(cols, args_figdir)
        fig_scatter(cols, args_figdir)
        fig_correlacao(cols, args_figdir)

    print("Concluido.")


def main():
    ap = argparse.ArgumentParser(description="Gera figuras a partir dos CSVs das rodadas.")
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--figdir", default="figuras")
    ap.add_argument("--tag", default=None, help="cenario especifico p/ figuras temporais")
    a = ap.parse_args()
    generate_all(a.results_dir, a.figdir, a.tag)


if __name__ == "__main__":
    main()
