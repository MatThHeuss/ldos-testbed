"""
infra.py — Coleta de metricas de infraestrutura e auto-scaler simulado.

No testbed local as fontes 'docker stats' / 'docker exec' / 'auto-scaling' da
tese sao aproximadas por proxies:
  - CPU% / MEM%      -> psutil sobre o processo do testbed
  - processos httpd  -> nº de workers ocupados no servidor (in-service)
  - conteineres N(t) -> AutoScaler simulado (politica tipo HPA/KEDA) sobre a carga

No ambiente Docker real, troque InfraCollector.sample() por chamadas a
`docker stats --no-stream` / `docker exec <c> pgrep -c httpd` / contagem de
replicas, mantendo o mesmo esquema de amostra. O extrator de features nao muda.
"""
import threading
import time

import psutil


class AutoScaler:
    """Auto-scaler simulado -> gera a serie N(t) (conteineres ativos, EDoS).

    Le um sinal de carga (workers ocupados) e ajusta o nº de replicas por uma
    politica de utilizacao com cooldown. NAO altera a capacidade do servidor
    (fixa neste testbed); e um sinal observavel para o dataset. No Docker real,
    as replicas mudariam a capacidade de fato.
    """
    def __init__(self, enabled=True, min_replicas=1, max_replicas=10,
                 capacity_per_replica=4, scale_up_util=0.8, scale_down_util=0.3,
                 cooldown_s=1.0):
        self.enabled = enabled
        self.min_replicas = min_replicas
        self.max_replicas = max_replicas
        self.cap = max(1, capacity_per_replica)
        self.up = scale_up_util
        self.down = scale_down_util
        self.cooldown = cooldown_s
        self.replicas = min_replicas
        self._last_change = 0.0

    def step(self, busy, t):
        if not self.enabled:
            return self.replicas
        util = busy / (self.cap * self.replicas) if self.replicas > 0 else 1.0
        if t - self._last_change >= self.cooldown:
            if util > self.up and self.replicas < self.max_replicas:
                self.replicas += 1
                self._last_change = t
            elif util < self.down and self.replicas > self.min_replicas:
                self.replicas -= 1
                self._last_change = t
        return self.replicas


def gera_series_N(occ_samples, capacity, scale_up=0.8, scale_down=0.3,
                  cooldown_s=1.0, min_replicas=1, max_replicas=10):
    """Aplica o auto-scaler simulado sobre uma serie de ocupacao, gerando N(t).

    Fonte unica da politica de auto-scaling, reutilizada tanto pelo orquestrador
    (geracao em tempo real durante o experimento) quanto pelo pos-processamento
    (calculo do custo/scaling sobre um dataset ja gerado), garantindo N(t) identico.

    capacity: capacidade do servidor (= capacidade por replica; cada replica
    corresponde a um servidor identico ao do testbed).
    occ_samples: lista de (t, ocupacao). Retorna lista de N (int) alinhada a ela.
    """
    asc = AutoScaler(enabled=True, min_replicas=min_replicas, max_replicas=max_replicas,
                     capacity_per_replica=capacity, scale_up_util=scale_up,
                     scale_down_util=scale_down, cooldown_s=cooldown_s)
    return [asc.step(occ, t) for (t, occ) in occ_samples]


class InfraCollector:
    """Thread que amostra CPU/MEM/workers/replicas a cada `interval` segundos."""
    def __init__(self, load_fn, interval=0.2, autoscaler=None):
        self.load_fn = load_fn            # callable -> workers ocupados no momento
        self.interval = interval
        self.autoscaler = autoscaler or AutoScaler(enabled=False)
        self.samples = []                 # (t, cpu_pct, mem_pct, httpd_procs, containers)
        self.running = threading.Event()
        self._proc = psutil.Process()
        self._th = None

    def _loop(self):
        self._proc.cpu_percent(None)      # prime (primeira leitura retorna 0)
        while self.running.is_set():
            time.sleep(self.interval)
            t = time.time()
            busy = self.load_fn()
            cpu = self._proc.cpu_percent(None)          # % desde a ultima leitura
            mem = self._proc.memory_percent()           # % de RAM do sistema
            containers = self.autoscaler.step(busy, t)
            self.samples.append((t, cpu, mem, busy, containers))

    def start(self):
        self.running.set()
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()

    def stop(self):
        self.running.clear()
        if self._th:
            self._th.join(timeout=2 * self.interval + 1)