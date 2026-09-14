"""
features.py — Extrator de features por janela temporal (gera o dataset rotulado).

Consome o fluxo normalizado de PktRecords (de server.py ou, no futuro, de um
.pcap real) + metricas de cliente + amostras de infra, e emite UMA LINHA POR
JANELA com as 20 features abaixo e o rotulo (benign / <ataque>).

Mapeamento feature -> categoria da tese:
  Volume        : pkt_count, byte_count, active_conns_mean
  Distribuicao  : src_ip_entropy, src_port_entropy, distinct_src_ips, distinct_src_ports
  Temporalidade : iat_mean, iat_var, conn_duration_mean
  Protocolo     : syn_ratio, http_incomplete_count, pkt_size_mean
  Infra/impacto : cpu_pct, mem_mib, httpd_procs, availability_A, rt_mean,
                  refused_rate, containers_N

A rotulagem e por presenca de trafego do atacante na janela (tag == attacker),
o que rotula naturalmente janelas de aquecimento benigno como 'benign'.
"""
from collections import Counter, defaultdict

from capture import shannon_entropy

FEATURE_ORDER = [
    "window_start", "window_end", "label",
    # Volume
    "pkt_count", "byte_count", "active_conns_mean",
    # Distribuicao
    "src_ip_entropy", "src_port_entropy", "distinct_src_ips", "distinct_src_ports",
    # Temporalidade
    "iat_mean", "iat_var", "conn_duration_mean",
    # Protocolo
    "syn_ratio", "http_incomplete_count", "pkt_size_mean",
    # Infraestrutura e impacto
    "cpu_pct", "mem_mib", "httpd_procs", "availability_A", "rt_mean",
    "refused_rate", "containers_N",
    # auxiliares (uteis p/ analise; nao sao features obrigatorias)
    "attacker_pkts", "legit_pkts",
]


def _mean(xs):
    return sum(xs) / len(xs) if xs else None


def _variance(xs):
    if len(xs) < 2:
        return 0.0
    m = sum(xs) / len(xs)
    return sum((x - m) ** 2 for x in xs) / (len(xs) - 1)


def _overlap(a0, a1, b0, b1):
    return max(0.0, min(a1, b1) - max(a0, b0))


def extract_windows(pkts, conn_open, conn_close, legit_log, infra_samples,
                    t0, t_end, window, attack_label="lordas",
                    attack_start=None, attack_end=None, recovery_label="recovery"):
    if t_end <= t0:
        return []
    n_windows = int((t_end - t0) / window) + 1

    # baldes por janela
    wp = defaultdict(list)          # pacotes
    for p in pkts:
        if t0 <= p.t < t_end:
            wp[int((p.t - t0) / window)].append(p)

    wl = defaultdict(list)          # metricas de cliente legitimo
    for (ts, seq, outcome, rt) in legit_log:
        if t0 <= ts < t_end and outcome in ("served", "refused"):
            wl[int((ts - t0) / window)].append((outcome, rt))

    wi = defaultdict(list)          # amostras de infra
    for s in infra_samples:
        ts = s[0]
        if t0 <= ts < t_end:
            wi[int((ts - t0) / window)].append(s)

    # intervalos de conexao (para concorrencia e duracao)
    conn_iv = {}
    for cid, t_open in conn_open.items():
        t_close = conn_close.get(cid, t_end)
        conn_iv[cid] = (t_open, max(t_close, t_open))

    rows = []
    for w in range(n_windows):
        ws = t0 + w * window
        we = min(ws + window, t_end)
        pk = wp.get(w, [])
        inbound = [p for p in pk if p.direction == "in"]
        syns = [p for p in pk if p.is_syn]              # 1 SYN por conexao (entrada)

        # ---- Volume ----
        pkt_count = len(pk)
        byte_count = sum(p.size for p in pk)
        # concorrencia media = integral da sobreposicao / duracao da janela
        wlen = (we - ws) or 1e-9
        overlap_sum = sum(_overlap(o, c, ws, we) for (o, c) in conn_iv.values())
        active_conns_mean = overlap_sum / wlen

        # ---- Distribuicao (sobre pacotes de ENTRADA; origem = cliente) ----
        ip_counts = Counter(p.src_ip for p in inbound)
        port_counts = Counter(p.src_port for p in inbound)
        src_ip_entropy = shannon_entropy(ip_counts)
        src_port_entropy = shannon_entropy(port_counts)
        distinct_src_ips = len(ip_counts)
        distinct_src_ports = len(port_counts)

        # ---- Temporalidade ----
        # IAT sobre CHEGADAS DE CONEXAO (timestamps de SYN) na janela
        syn_times = sorted(p.t for p in syns)
        iats = [b - a for a, b in zip(syn_times, syn_times[1:])]
        iat_mean = _mean(iats)
        iat_var = _variance(iats)
        # duracao media das conexoes que ABRIRAM nesta janela
        durs = [max(0.0, conn_iv[cid][1] - conn_iv[cid][0])
                for cid, (o, _) in conn_iv.items() if ws <= o < we]
        conn_duration_mean = _mean(durs)

        # ---- Protocolo ----
        syn_ratio = (len(syns) / pkt_count) if pkt_count else 0.0
        http_incomplete_count = sum(1 for p in inbound if p.kind == "req" and not p.http_complete)
        pkt_size_mean = (byte_count / pkt_count) if pkt_count else 0.0

        # ---- Infra / impacto ----
        infra = wi.get(w, [])
        cpu_pct = _mean([s[1] for s in infra])
        mem_mib = _mean([s[2] for s in infra])
        httpd_procs = _mean([s[3] for s in infra])
        containers_N = infra[-1][4] if infra else None   # ultimo valor observado

        cl = wl.get(w, [])
        served = sum(1 for (o, _) in cl if o == "served")
        refused = sum(1 for (o, _) in cl if o == "refused")
        tot = served + refused
        availability_A = (served / tot) if tot else None
        refused_rate = (refused / tot) if tot else None
        rt_mean = _mean([rt for (o, rt) in cl if o == "served"])

        # ---- Rotulo (por fase temporal) ----
        # Usa o ponto medio da janela (relativo a t0) para decidir a fase.
        # Antes do ataque: benign; durante: <ataque>; depois: recovery.
        # A fase de recuperacao recebe rotulo proprio para nao confundir janelas
        # com o pool ainda saturado (rescaldo do ataque) com trafego benigno normal.
        if attack_start is not None and attack_end is not None:
            w_mid = (ws - t0 + we - t0) / 2.0
            if w_mid < attack_start:
                label = "benign"
            elif w_mid < attack_end:
                label = attack_label
            else:
                label = recovery_label
        else:
            # comportamento antigo: por presenca de trafego do atacante
            label = attack_label if any(p.tag == "attacker" for p in pk) else "benign"
        attacker_pkts = sum(1 for p in pk if p.tag == "attacker")
        legit_pkts = sum(1 for p in pk if p.tag == "legit")

        rows.append({
            "window_start": round(ws - t0, 4), "window_end": round(we - t0, 4),
            "label": label,
            "pkt_count": pkt_count, "byte_count": byte_count,
            "active_conns_mean": round(active_conns_mean, 4),
            "src_ip_entropy": round(src_ip_entropy, 4),
            "src_port_entropy": round(src_port_entropy, 4),
            "distinct_src_ips": distinct_src_ips, "distinct_src_ports": distinct_src_ports,
            "iat_mean": round(iat_mean, 6) if iat_mean is not None else "",
            "iat_var": round(iat_var, 8),
            "conn_duration_mean": round(conn_duration_mean, 6) if conn_duration_mean is not None else "",
            "syn_ratio": round(syn_ratio, 4),
            "http_incomplete_count": http_incomplete_count,
            "pkt_size_mean": round(pkt_size_mean, 2),
            "cpu_pct": round(cpu_pct, 2) if cpu_pct is not None else "",
            "mem_mib": round(mem_mib, 2) if mem_mib is not None else "",
            "httpd_procs": round(httpd_procs, 2) if httpd_procs is not None else "",
            "availability_A": round(availability_A, 4) if availability_A is not None else "",
            "rt_mean": round(rt_mean, 6) if rt_mean is not None else "",
            "refused_rate": round(refused_rate, 4) if refused_rate is not None else "",
            "containers_N": containers_N if containers_N is not None else "",
            "attacker_pkts": attacker_pkts, "legit_pkts": legit_pkts,
        })
    return rows
