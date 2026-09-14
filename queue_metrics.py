"""
queue_metrics.py — Métricas de OCUPAÇÃO DA FILA e recusas (para reporte).

NAO faz parte do dataset de features (que contem exatamente as 20 features
especificadas). Sao metricas auxiliares para a secao de resultados: o quanto a
fila de servico fica ocupada, quando satura (occupied == capacity) e quantas
requisicoes sao recusadas por fila cheia.

Derivadas de:
  - server.occ_events : transicoes (t, occupied) -> funcao escada de ocupacao
  - server.req_log    : (t, tag, seq, outcome, occupied) -> recusas/aceites
"""


def occupancy_aggregate(occ_events, capacity):
    """Estatisticas ponderadas no tempo: ocupacao media, pico e fracao com fila cheia."""
    ev = sorted(occ_events)
    if len(ev) < 2:
        return {"occ_mean": None, "occ_peak": None, "full_fraction": None}
    total = ev[-1][0] - ev[0][0]
    area = full = 0.0
    peak = 0
    for (t1, o), (t2, _) in zip(ev, ev[1:]):
        dt = t2 - t1
        area += o * dt
        if o >= capacity:
            full += dt
        if o > peak:
            peak = o
    peak = max(peak, ev[-1][1])
    if total <= 0:
        return {"occ_mean": None, "occ_peak": peak, "full_fraction": None}
    return {"occ_mean": area / total, "occ_peak": peak, "full_fraction": full / total}


def refusal_counts(req_log):
    """Total de recusas (fila cheia) e separacao atacante/legitimo."""
    tot = att = leg = 0
    for (_t, tag, _seq, outcome, _occ) in req_log:
        if outcome == "refuse":
            tot += 1
            if tag == "attacker":
                att += 1
            elif tag == "legit":
                leg += 1
    return {"refused_total": tot, "refused_attacker": att, "refused_legit": leg}


def occupancy_windows(occ_events, req_log, capacity, t0, t_end, window):
    """Serie temporal por janela: ocupacao media/pico, fracao cheia, recusas/aceites."""
    ev = sorted(occ_events)
    segs = [(ev[i][0], ev[i + 1][0], ev[i][1]) for i in range(len(ev) - 1)] if len(ev) >= 2 else []
    n = int((t_end - t0) / window) + 1
    ref = [0] * n
    acc = [0] * n
    for (t, _tag, _seq, outcome, _occ) in req_log:
        if t0 <= t < t_end:
            w = int((t - t0) / window)
            if outcome == "refuse":
                ref[w] += 1
            elif outcome == "accept":
                acc[w] += 1
    rows = []
    for w in range(n):
        ws = t0 + w * window
        we = min(ws + window, t_end)
        wlen = (we - ws) or 1e-9
        area = full = 0.0
        peak = 0
        for (s0, s1, o) in segs:
            ov = min(s1, we) - max(s0, ws)
            if ov > 0:
                area += o * ov
                if o >= capacity:
                    full += ov
                if o > peak:
                    peak = o
        rows.append({
            "window_start": round(ws - t0, 4), "window_end": round(we - t0, 4),
            "occ_mean": round(area / wlen, 4), "occ_peak": peak,
            "full_fraction": round(full / wlen, 4),
            "refused": ref[w], "accepted": acc[w],
        })
    return rows


QUEUE_FIELDS = ["window_start", "window_end", "occ_mean", "occ_peak",
                "full_fraction", "refused", "accepted"]
