"""
server.py — Servidor de aplicacao concorrente com fila de servico finita.

Modela o alvo do LoRDAS (Maciá-Fernández et al., 2009) E atua como ponto de
captura tipo PCAP: para cada conexao emite PktRecords normalizados (SYN, REQ,
RESP/RST) com IP de origem logico, porta de origem real (getpeername), bytes e
completude HTTP. Esses registros alimentam o extrator de features.

  - queue_size : posicoes totais na fila (uma requisicao ocupa uma posicao da
                 aceitacao ao fim do servico). occupied == queue_size => recusa.
  - n_workers  : N_s workers concorrentes. T_s ~ N(ts_mean, ts_var) [var=variancia].
Evento "posicao liberada" = worker completa o servico.
"""
import queue
import socket
import threading

from capture import Capture, PktRecord
from common import RESP_BUSY, RESP_OK, now, parse_request, sample_positive_normal


class VulnerableServer:
    def __init__(self, host="127.0.0.1", port=8080, n_workers=4, queue_size=4,
                 ts_mean=0.1, ts_var=1e-4, backlog=1024, header_overhead=40,
                 idle_timeout=None, service_work=0, conn_mem_kb=0, capture: Capture = None):
        self.host, self.port = host, port
        self.n_workers = n_workers
        self.capacity = queue_size
        self.ts_mean, self.ts_var = ts_mean, ts_var
        self.backlog = backlog
        self.header = header_overhead
        # idle_timeout (t_k): se definido, conexoes com requisicao INCOMPLETA (hc=0)
        # nao sao servidas em T_s; ocupam a posicao ate serem renovadas (novos bytes)
        # ou ate ficarem ociosas > idle_timeout, quando sao derrubadas. E o mecanismo
        # do Slowloris. Se None (padrao, usado por LoRDAS), o comportamento e o antigo:
        # TODA conexao vai para a work_q e e servida em T_s.
        self.idle_timeout = idle_timeout
        # Consumo de recursos REAL (opt-in; medivel por docker stats / psutil):
        #  - service_work: nº de iteracoes de trabalho de CPU por requisicao SERVIDA.
        #    Conexoes seguradas (Slowloris) nao passam pelo worker -> nao gastam CPU,
        #    reproduzindo a assinatura "CPU baixa" do Slowloris.
        #  - conn_mem_kb: memoria (KB) alocada e residente por conexao ATIVA (ocupa
        #    posicao), liberada ao encerrar. A memoria cresce com o nº de conexoes.
        self.service_work = int(service_work)
        self.conn_mem_kb = int(conn_mem_kb)
        self._conn_mem = {}                     # cid -> bytearray (memoria residente)
        self._mem_lock = threading.Lock()
        self.capture = capture or Capture()

        self.occupied = 0
        self.occ_lock = threading.Lock()
        self.work_q = queue.Queue()
        self.running = threading.Event()
        self.sock = None
        self.workers = []
        self.listener = None

        self._conn_counter = 0
        self._cid_lock = threading.Lock()

        # metricas
        self.occ_events = []   # (t, occupied) -> para C e concorrencia
        self.req_log = []      # (t, tag, seq, outcome, occupied_after)
        self.log_lock = threading.Lock()
        self.t0 = None

    def _mem_alloc(self, cid):
        # aloca memoria residente para uma conexao ativa (toca as paginas)
        if self.conn_mem_kb > 0:
            buf = bytearray(self.conn_mem_kb * 1024)
            for i in range(0, len(buf), 4096):
                buf[i] = 1                       # forca residencia (RSS)
            with self._mem_lock:
                self._conn_mem[cid] = buf

    def _mem_free(self, cid):
        if self.conn_mem_kb > 0:
            with self._mem_lock:
                self._conn_mem.pop(cid, None)

    def _cpu_work(self):
        # trabalho de CPU real por requisicao servida (busy loop calibravel)
        x = 0.0
        for i in range(self.service_work):
            x += (i * 1.000001) ** 0.5
        return x

    def _next_cid(self):
        with self._cid_lock:
            self._conn_counter += 1
            return self._conn_counter

    def _log_occ(self, t):
        self.occ_events.append((t, self.occupied))

    def _record(self, t, tag, seq, outcome):
        with self.log_lock:
            self.req_log.append((t, tag, seq, outcome, self.occupied))

    def busy_workers(self):
        """Workers ocupados no momento (proxy de 'processos httpd ativos')."""
        return self.occupied

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(self.backlog)
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self.running.set()
        self.t0 = now()
        with self.occ_lock:
            self._log_occ(self.t0)
        for _ in range(self.n_workers):
            th = threading.Thread(target=self._worker, daemon=True)
            th.start()
            self.workers.append(th)
        self.listener = threading.Thread(target=self._listen, daemon=True)
        self.listener.start()

    def _listen(self):
        while self.running.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._admit, args=(conn,), daemon=True).start()

    def _emit(self, t, src_ip, src_port, size, is_syn, tag, cid, direction, kind, hc):
        self.capture.add(PktRecord(
            t=t, src_ip=src_ip, src_port=src_port, dst_ip=self.host, dst_port=self.port,
            size=size, is_syn=is_syn, tag=tag, conn_id=cid, direction=direction,
            kind=kind, http_complete=hc))

    def _admit(self, conn):
        conn.settimeout(2.0)
        cid = self._next_cid()
        try:
            try:
                peer_ip, peer_port = conn.getpeername()[:2]
            except OSError:
                peer_ip, peer_port = self.host, 0
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(256)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
            tag, seq, src_ip, hc = parse_request(data)
            t = now()
            self.capture.open_conn(cid, t)
            # --- pacotes de entrada: SYN + requisicao (porta de origem REAL) ---
            self._emit(t, src_ip, peer_port, self.header, True, tag, cid, "in", "syn", hc)
            self._emit(t, src_ip, peer_port, len(data) + self.header, False, tag, cid,
                       "in", "req", hc)

            admit = False
            with self.occ_lock:
                if self.occupied < self.capacity:
                    self.occupied += 1
                    self._log_occ(t)
                    admit = True
            if admit:
                self._record(t, tag, seq, "accept")
                self._mem_alloc(cid)            # memoria residente enquanto ativa
                if self.idle_timeout is not None and hc == 0:
                    # Slowloris: conexao incompleta ocupa a posicao ate renovar/expirar
                    self._hold(conn, tag, seq, src_ip, cid, peer_port)
                else:
                    # caminho padrao (LoRDAS/legitimo): servida em T_s pelos workers
                    self.work_q.put((conn, tag, seq, src_ip, hc, cid, peer_port))
            else:
                # recusa: RST de saida (sem payload de resposta) -> conexao curta
                self._record(t, tag, seq, "refuse")
                self._emit(now(), self.host, self.port, len(RESP_BUSY) + self.header,
                           False, tag, cid, "out", "rst", hc)
                self.capture.close_conn(cid, now())
                try:
                    conn.sendall(RESP_BUSY)
                except OSError:
                    pass
                conn.close()
        except (socket.timeout, OSError):
            self.capture.close_conn(cid, now())
            try:
                conn.close()
            except OSError:
                pass

    def _hold(self, conn, tag, seq, src_ip, cid, peer_port):
        """Segura uma conexao incompleta (Slowloris) ocupando a posicao. Cada bloco
        de bytes recebido (cabecalho parcial de renovacao) reseta o timer de
        inatividade. Se a conexao ficar ociosa mais que idle_timeout (t_k), ou o
        par fechar, a conexao e derrubada e a posicao liberada."""
        last = now()
        poll = min(self.idle_timeout, 1.0)
        conn.settimeout(poll)
        try:
            while self.running.is_set():
                try:
                    chunk = conn.recv(256)
                except socket.timeout:
                    if now() - last > self.idle_timeout:
                        break                       # ocioso > t_k -> derruba
                    continue
                except OSError:
                    break
                if not chunk:
                    break                           # par fechou a conexao
                # renovacao: reseta o timer e registra o cabecalho parcial
                last = now()
                self._emit(last, src_ip, peer_port, len(chunk) + self.header, False,
                           tag, cid, "in", "req", 0)
        finally:
            t = now()
            self._mem_free(cid)                 # libera memoria da conexao segurada
            self._emit(t, self.host, self.port, self.header, False, tag, cid,
                       "out", "rst", 0)
            self.capture.close_conn(cid, t)
            try:
                conn.close()
            except OSError:
                pass
            with self.occ_lock:
                self.occupied -= 1                  # POSICAO LIBERADA
                self._log_occ(t)
            self._record(t, tag, seq, "dropped")

    def _worker(self):
        while self.running.is_set():
            try:
                conn, tag, seq, src_ip, hc, cid, peer_port = self.work_q.get(timeout=0.2)
            except queue.Empty:
                continue
            ts = sample_positive_normal(self.ts_mean, self.ts_var)  # T_s ~ N(mean,var)
            # trabalho de CPU real por requisicao, depois aguarda o restante de T_s
            # (o servico dura ~T_s; a CPU sobe com o nº de requisicoes servidas)
            t_start = now()
            if self.service_work > 0:
                self._cpu_work()
            elapsed = now() - t_start
            if elapsed < ts:
                threading.Event().wait(ts - elapsed)
            try:
                conn.sendall(RESP_OK)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
            t = now()
            self._mem_free(cid)                 # libera memoria da conexao
            # pacote de saida: resposta
            self._emit(t, self.host, self.port, len(RESP_OK) + self.header, False, tag,
                       cid, "out", "resp", hc)
            self.capture.close_conn(cid, t)
            with self.occ_lock:
                self.occupied -= 1          # POSICAO LIBERADA
                self._log_occ(t)
            self._record(t, tag, seq, "complete")

    def stop(self):
        self.running.clear()
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        with self.occ_lock:
            self._log_occ(now())

    # ---- metrica C ----
    def client_success_probability(self):
        """C = fracao do tempo com >=1 posicao livre (occupied < capacity)."""
        ev = sorted(self.occ_events)
        if len(ev) < 2:
            return None
        total = ev[-1][0] - ev[0][0]
        if total <= 0:
            return None
        free_time = 0.0
        for (t1, occ), (t2, _) in zip(ev, ev[1:]):
            if occ < self.capacity:
                free_time += (t2 - t1)
        return free_time / total
