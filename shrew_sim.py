"""
shrew_sim.py — Simulador do ataque Shrew (Kuzmanovic & Knightly, SIGCOMM 2003).

Modelo de TAXA (fluido) com dinamica de RTO explicita, event-stepped:
  - Gargalo: capacidade C, buffer B. No baseline, o excesso agregado dos fluxos
    causa transbordo breve e reacao AIMD (corte pela metade), SEM timeout.
  - Atacante (onda quadrada <R, l, T>): a rajada sustentada mantem o gargalo
    saturado; quando a rajada dura >= RTT (condicao C1), forca os fluxos a timeout.
    Justificativa fisica: apenas uma injecao sustentada de alta taxa mantem a fila
    cheia por >= RTT; o TCP responsivo recua dentro de um RTT (self-congestion nao
    gera timeout, apenas AIMD).
  - RTO = minRTO (condicao C2, RTT homogeneo); ao expirar, o fluxo retransmite: se
    coincide com uma rajada -> perda -> backoff exponencial; senao -> sai do timeout
    via slow-start. Esse casamento reproduz os nulos em T = minRTO e minRTO/2.
  - Metrica: throughput normalizado agregado dos fluxos legitimos ao longo do tempo.

Unidades: taxas em Mb/s, tempos em s, tamanhos em Mb.
"""
import numpy as np

from capture import PktRecord


class ShrewSim:
    def __init__(self,
                 C=15.0, buffer_ms=30.0,
                 n_flows=20, rtt=0.04, minrto=1.0, mss_bytes=1500, G=0.1,
                 R=15.0, l=0.24, T=1.0, attack=True,
                 dt=0.005, duration=100.0, benign=10.0, recovery=10.0,
                 rto_cap=4.0, record_trace=False, pkt_sample=2,
                 seed=None):
        self.C = C
        self.B = C * (buffer_ms / 1000.0)
        self.n = n_flows
        self.rtt = rtt
        self.minrto = minrto
        self.mss = mss_bytes * 8 / 1e6
        self.G = G
        self.R = R
        self.l = l
        self.T = T
        self.attack = attack
        self.dt = dt
        self.duration = duration
        self.benign = benign
        self.recovery = recovery
        self.rto_cap = rto_cap
        self.record_trace = record_trace
        self.pkt_sample = max(1, int(pkt_sample))
        self.pkts = []
        self.rng = np.random.default_rng(seed)
        self.fair = C / n_flows

        self.ts = []
        self.rho = []
        self.qseries = []
        self.atk_on = []
        self.n_timeout = []

    def _attacker_rate(self, t):
        if not self.attack:
            return 0.0
        t0, t1 = self.benign, self.benign + self.duration
        if t < t0 or t >= t1:
            return 0.0
        return self.R if ((t - t0) % self.T) < self.l else 0.0

    def run(self):
        n, dt = self.n, self.dt
        total_t = self.benign + self.duration + self.recovery

        rate = np.full(n, self.fair)
        state = np.zeros(n, dtype=int)         # 0=normal, 1=timeout
        rto = np.full(n, self.minrto)
        t_out = np.zeros(n)
        backoff = np.zeros(n, dtype=int)
        in_ss = np.zeros(n, dtype=bool)
        ssthresh = np.full(n, self.C)

        # trace: IPs/portas de origem (legitimos distintos; atacante origem unica)
        flow_ips = [f"172.16.{(i // 254) % 254}.{(i % 254) + 1}" for i in range(n)]
        flow_ports = [20000 + i for i in range(n)]
        atk_ip = "10.0.0.1"
        acc = np.zeros(n)          # bytes acumulados por fluxo (Mb)
        acc_atk = 0.0
        syn_sent = np.zeros(n, dtype=bool)
        mss_bytes = int(self.mss * 1e6 / 8)
        psz = self.pkt_sample * mss_bytes + 40

        q = 0.0
        prev_atk = False
        burst_start = -1e9
        burst_timed_out = False                # ja forcou timeout nesta rajada?

        for k in range(int(total_t / dt)):
            t = k * dt
            atk = self._attacker_rate(t)
            burst = atk > 0.0
            if burst and not prev_atk:
                burst_start = t
                burst_timed_out = False
            prev_atk = burst
            burst_elapsed = (t - burst_start) if burst else 0.0

            normal = state == 0
            offered = rate[normal].sum() + atk
            q = min(self.B, max(0.0, q + (offered - self.C) * dt))
            full = q >= self.B - 1e-9

            # baseline (sem atacante): transbordo breve -> AIMD (corte), sem timeout
            if full and not burst:
                md = normal & (rate > self.fair * 0.5)
                rate[md] *= 0.5
                ssthresh[md] = np.maximum(rate[md], self.mss / self.rtt)
                in_ss[md] = False

            # C1: rajada sustentada (>= RTT) forca timeout dos fluxos normais (1x/rajada)
            severe = burst and burst_elapsed >= self.rtt
            if severe and not burst_timed_out:
                to = normal & (rate > 0)
                state[to] = 1
                backoff[to] = 0
                rto[to] = self.minrto
                t_out[to] = t + self.minrto
                rate[to] = 0.0
                burst_timed_out = True

            # retransmissao ao expirar o RTO
            expired = (state == 1) & (t >= t_out)
            if expired.any():
                if burst:                       # coincide com rajada -> perda -> backoff
                    backoff[expired] += 1
                    rto[expired] = np.minimum(self.minrto * (2.0 ** backoff[expired]), self.rto_cap)
                    t_out[expired] = t + rto[expired]
                else:                           # sucesso -> slow-start
                    state[expired] = 0
                    in_ss[expired] = True
                    ssthresh[expired] = np.maximum(ssthresh[expired], self.fair)
                    rate[expired] = self.mss / self.rtt
                    backoff[expired] = 0

            # crescimento dos fluxos normais (fora de rajada severa)
            normal = state == 0
            grow = normal & (~severe)
            ss = grow & in_ss
            rate[ss] *= 2.0 ** (dt / self.rtt)
            in_ss[ss & (rate >= ssthresh)] = False
            ca = grow & (~in_ss)
            rate[ca] += self.mss * dt / (self.rtt ** 2)
            np.minimum(rate, self.C, out=rate)

            if self.record_trace:
                self._emit(t, rate, state, atk, acc, syn_sent, flow_ips,
                           flow_ports, mss_bytes, psz)
                if atk > 0:
                    acc_atk += atk * dt
                    natk = int((acc_atk * 1e6 / 8) // (self.pkt_sample * mss_bytes))
                    if natk > 0:
                        acc_atk -= natk * self.pkt_sample * mss_bytes * 8 / 1e6
                        for _ in range(natk):
                            self.pkts.append(PktRecord(
                                t=t, src_ip=atk_ip, src_port=int(self.rng.integers(1024, 65535)),
                                dst_ip="192.168.0.1", dst_port=80, size=psz, is_syn=False,
                                tag="attacker", conn_id=-1, direction="in", kind="atk",
                                http_complete=True))

            good = 0.0 if severe else min(rate[state == 0].sum(), self.C)
            self.ts.append(t)
            self.rho.append(good / self.C)
            self.qseries.append(q)
            self.atk_on.append(1 if burst else 0)
            self.n_timeout.append(int((state == 1).sum()))

        return self

    def _emit(self, t, rate, state, atk, acc, syn_sent, ips, ports, mss_bytes, psz):
        # acumula bytes por fluxo normal e emite super-pacotes (amostrados)
        normal = state == 0
        acc[normal] += rate[normal] * self.dt        # Mb
        thr = self.pkt_sample * mss_bytes * 8 / 1e6   # Mb por super-pacote
        for i in np.nonzero(acc >= thr)[0]:
            npk = int(acc[i] // thr)
            acc[i] -= npk * thr
            cid = int(i)
            if not syn_sent[i]:
                self.pkts.append(PktRecord(t=t, src_ip=ips[i], src_port=ports[i],
                    dst_ip="192.168.0.1", dst_port=80, size=40, is_syn=True, tag="legit",
                    conn_id=cid, direction="in", kind="syn", http_complete=True))
                syn_sent[i] = True
            for _ in range(npk):
                self.pkts.append(PktRecord(t=t, src_ip=ips[i], src_port=ports[i],
                    dst_ip="192.168.0.1", dst_port=80, size=psz, is_syn=False, tag="legit",
                    conn_id=cid, direction="in", kind="data", http_complete=True))

    def mean_rho(self, phase):
        ts, rho = np.array(self.ts), np.array(self.rho)
        if phase == "benign":
            m = ts < self.benign
        elif phase == "attack":
            m = (ts >= self.benign) & (ts < self.benign + self.duration)
        elif phase == "recovery":
            m = ts >= self.benign + self.duration
        else:
            m = np.ones_like(ts, dtype=bool)
        return float(rho[m].mean()) if m.any() else None
