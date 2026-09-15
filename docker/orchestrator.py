"""
orchestrator.py — Orquestrador do experimento LDoS no Docker (host, Forma 2).

Roda no HOST e comanda os containers via CLI do docker (subprocess). Executa UM
cenario com tres fases (benigno -> ataque -> recuperacao):

  1. cria a rede e sobe o container do SERVIDOR (recursos reais: docker stats mede)
  2. sobe o container do CLIENTE LEGITIMO (roda o experimento inteiro)
  3. espera a fase benigna; sobe o container do ATACANTE; espera a fase de ataque;
     para o atacante
  4. espera a recuperacao; para o legitimo e o servidor
  5. coleta docker stats (CPU/memoria) e a ocupacao real do pool a cada 1s, em paralelo
  6. junta os dumps (captura do servidor + log do legitimo + docker stats) e monta o
     dataset com as 20 features via features.extract_windows

Pre-requisitos: imagem 'ldos-testbed' ja construida; docker sem sudo.
Uso:
  python docker/orchestrator.py --attack slowloris --outdir run1 \
      --benign 15 --attack-dur 40 --recovery 15
"""
import argparse
import csv
import json
import os
import subprocess
import sys
import threading
import time

# garante que os modulos do projeto (raiz) sejam encontrados, mesmo rodando
# 'python docker/orchestrator.py' de dentro da pasta docker/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# modulos do projeto (o orquestrador roda no host, na raiz do projeto)
from features import FEATURE_ORDER, extract_windows
from capture import PktRecord
from infra import gera_series_N

IMAGE = "ldos-testbed"
NET = "ldos-net"
SERVER = "ldos-server"
LEGIT = "ldos-legit"
ATTACKER = "ldos-attacker"


def sh(args, check=True, capture=False):
    """Executa um comando docker. Retorna stdout se capture=True."""
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"comando falhou: {' '.join(args)}\n{r.stderr.strip()}")
    return r.stdout if capture else r


def cleanup():
    for name in (LEGIT, ATTACKER, SERVER):
        subprocess.run(["docker", "rm", "-f", name],
                       capture_output=True, text=True)


def ensure_network():
    r = subprocess.run(["docker", "network", "inspect", NET],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sh(["docker", "network", "create", NET])


# ----------------------------------------------------------------------------
# coleta de infra (docker stats + ocupacao real do pool) a cada 1s, em thread
# ----------------------------------------------------------------------------
def parse_stats_line(line):
    # formato: "CPU%|MEMUSAGE / LIMIT|PIDS" (definido pelo --format)
    try:
        cpu_s, mem_s, pids_s = line.split("|")
        cpu = float(cpu_s.strip().rstrip("%"))
        mem_use = mem_s.split("/")[0].strip()          # ex "51.2MiB"
        num = float("".join(c for c in mem_use if (c.isdigit() or c == ".")))
        unit = "".join(c for c in mem_use if c.isalpha())
        mib = num / 1024 if unit.startswith("KiB") else (num * 1024 if unit.startswith("GiB") else num)
        pids = int(pids_s.strip())
        return cpu, mib, pids
    except (ValueError, IndexError):
        return None


def strip_ansi(s):
    # docker stats em streaming intercala codigos ANSI: mover cursor (\x1b[H),
    # limpar tela (\x1b[J), limpar linha (\x1b[K), etc. Remove qualquer sequencia
    # CSI (\x1b[ ... <letra final>).
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "\x1b" and i + 1 < n and s[i + 1] == "[":
            i += 2
            while i < n and not s[i].isalpha():   # parametros (digitos, ';')
                i += 1
            i += 1                                 # consome a letra final do codigo
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def infra_collector(samples, proc_holder, stop):
    """docker stats em STREAMING: emite uma linha por segundo (granularidade real de
    1s), sem a latencia repetida do --no-stream. So CPU/memoria; a ocupacao do pool
    vem depois, do dump server_occ_events.csv, alinhada por timestamp."""
    proc = subprocess.Popen(
        ["docker", "stats", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}", SERVER],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    proc_holder.append(proc)
    last_t = 0.0
    for raw in proc.stdout:
        if stop.is_set():
            break
        parsed = parse_stats_line(strip_ansi(raw).strip())
        if parsed is None:
            continue
        t = time.time()
        # o docker stats emite cada atualizacao repetida (pares); mantem ~2 amostras/s
        # no maximo, evitando duplicatas exatas consecutivas.
        if t - last_t < 0.4:
            continue
        last_t = t
        cpu, mib, pids = parsed
        samples.append((t, cpu, mib, pids))       # (t, cpu, mib, pids)
    try:
        proc.terminate()
    except OSError:
        pass


def occ_at(occ_events, t):
    """Ocupacao do pool no instante t (funcao escada: ultimo evento com t_ev <= t)."""
    val = 0
    for t_ev, occ in occ_events:
        if t_ev <= t:
            val = occ
        else:
            break
    return val


# ----------------------------------------------------------------------------
# execucao de um cenario
# ----------------------------------------------------------------------------
def run_scenario(p):
    outdir = p["outdir"]
    data_dir = os.path.abspath(os.path.join(outdir, "data"))
    os.makedirs(data_dir, exist_ok=True)
    # limpa dumps antigos
    for f in os.listdir(data_dir):
        os.remove(os.path.join(data_dir, f))

    cleanup()
    ensure_network()

    total = p["benign"] + p["attack_dur"] + p["recovery"]

    # 1. servidor (recursos reais; idle_timeout liga o modo Slowloris)
    server_env = ["-e", f"SERVICE_WORK={p['service_work']}",
                  "-e", f"CONN_MEM_KB={p['conn_mem_kb']}",
                  "-e", f"N_WORKERS={p['capacity']}",
                  "-e", f"QUEUE_SIZE={p['capacity']}",
                  "-e", f"TS_MEAN={p['ts_mean']}"]
    if p["attack"] == "slowloris":
        server_env += ["-e", f"IDLE_TIMEOUT={p['t_k']}"]
    sh(["docker", "run", "-d", "--name", SERVER, "--network", NET,
        "-v", f"{data_dir}:/data", *server_env, IMAGE])
    time.sleep(1.0)
    print(f"[orq] servidor no ar. Logs:")
    print("   " + sh(["docker", "logs", SERVER], capture=True).strip())

    t0 = time.time()
    # coletor de infra em STREAMING, em paralelo (o experimento inteiro)
    samples = []
    proc_holder = []
    stop = threading.Event()
    collector = threading.Thread(target=infra_collector, args=(samples, proc_holder, stop),
                                 daemon=True)
    collector.start()

    # 2. cliente legitimo (roda benigno+ataque+recuperacao)
    legit_env = ["-e", "ROLE=legit", "-e", f"SERVER_HOST={SERVER}",
                 "-e", f"DURATION={total}", "-e", f"LAM={p['lam']}",
                 "-e", f"LEGIT_SRC_IPS={p['legit_src_ips']}"]
    sh(["docker", "run", "-d", "--name", LEGIT, "--network", NET,
        "-v", f"{data_dir}:/data", *legit_env, IMAGE,
        "python", "entrypoint_client.py"])
    print(f"[orq] fase BENIGNA ({p['benign']}s)...")
    time.sleep(p["benign"])

    # 3. atacante (fase de ataque)
    if p["attack"] == "slowloris":
        atk_env = ["-e", "ROLE=slowloris", "-e", f"SERVER_HOST={SERVER}",
                   "-e", f"DURATION={p['attack_dur']}", "-e", f"N_CONNS={p['n_conns']}",
                   "-e", f"DELTA={p['delta']}"]
    else:  # lordas
        atk_env = ["-e", "ROLE=lordas", "-e", f"SERVER_HOST={SERVER}",
                   "-e", f"DURATION={p['attack_dur']}", "-e", f"DELTA={p['delta']}",
                   "-e", f"T_ONTIME={p['t_ontime']}", "-e", f"T_OFFTIME={p['t_offtime']}"]
    print(f"[orq] fase de ATAQUE ({p['attack']}, {p['attack_dur']}s)...")
    sh(["docker", "run", "-d", "--name", ATTACKER, "--network", NET,
        "-v", f"{data_dir}:/data", *atk_env, IMAGE,
        "python", "entrypoint_client.py"])
    time.sleep(p["attack_dur"])
    subprocess.run(["docker", "stop", ATTACKER], capture_output=True, text=True)
    print(f"[orq] atacante parado.")

    # 4. recuperacao
    print(f"[orq] fase de RECUPERACAO ({p['recovery']}s)...")
    time.sleep(p["recovery"])

    # para o coletor (streaming), o legitimo e o servidor (dumps no SIGTERM)
    stop.set()
    for pr in proc_holder:
        try:
            pr.terminate()
        except OSError:
            pass
    collector.join(timeout=3)
    subprocess.run(["docker", "stop", LEGIT], capture_output=True, text=True)
    subprocess.run(["docker", "stop", SERVER], capture_output=True, text=True)
    time.sleep(1.0)
    print(f"[orq] experimento encerrado. {len(samples)} amostras de infra coletadas.")

    # carrega a ocupacao real do pool (dump do servidor) e alinha por timestamp com
    # as amostras de docker stats. Como os containers compartilham o relogio do host,
    # os timestamps do servidor e do host sao a mesma base (epoch).
    occ_events = []
    opath = os.path.join(data_dir, "server_occ_events.csv")
    if os.path.exists(opath):
        for r in csv.DictReader(open(opath)):
            occ_events.append((float(r["t"]), int(r["occupied"])))
    occ_events.sort()

    # ocupacao do pool alinhada a cada amostra de docker stats
    occ_por_amostra = [(t, occ_at(occ_events, t)) for (t, cpu, mib, pids) in samples]
    # auto-scaler simulado -> serie N(t) (numero de replicas), base do EDoS.
    # capacidade por replica = capacidade do servidor deste ataque.
    N_series = gera_series_N(occ_por_amostra, capacity=p["capacity"])

    # (t, cpu_pct, mem_mib, httpd_procs=ocupacao real, containers=N(t))
    infra_samples = [(t, cpu, mib, occ_at(occ_events, t), N_series[i])
                     for i, (t, cpu, mib, pids) in enumerate(samples)]

    # grava a serie de infra (para inspecao)
    with open(os.path.join(outdir, "infra_series.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "cpu_pct", "mem_mib", "occupancy", "containers"])
        w.writerows(infra_samples)

    return build_dataset(p, data_dir, infra_samples, t0, t0 + total)


def build_dataset(p, data_dir, infra_samples, t0, t_end):
    # 1. pacotes do servidor
    pkts = []
    ppath = os.path.join(data_dir, "server_pkts.csv")
    if os.path.exists(ppath):
        for r in csv.DictReader(open(ppath)):
            pkts.append(PktRecord(
                t=float(r["t"]), src_ip=r["src_ip"], src_port=int(r["src_port"]),
                dst_ip=r["dst_ip"], dst_port=int(r["dst_port"]), size=int(r["size"]),
                is_syn=(r["is_syn"] == "True"), tag=r["tag"], conn_id=int(r["conn_id"]),
                direction=r["direction"], kind=r["kind"],
                http_complete=(r["http_complete"] == "True")))
    # 2. ciclo de vida das conexoes
    conn_open, conn_close = {}, {}
    lpath = os.path.join(data_dir, "server_conn_lifecycle.json")
    if os.path.exists(lpath):
        life = json.load(open(lpath))
        conn_open = {int(k): v for k, v in life["open"].items()}
        conn_close = {int(k): v for k, v in life["close"].items()}
    # 3. log do legitimo
    legit_log = []
    glog = os.path.join(data_dir, "legit_log.csv")
    if os.path.exists(glog):
        for r in csv.DictReader(open(glog)):
            legit_log.append((float(r["t_send"]), int(r["seq"]), r["outcome"],
                              float(r["rt"])))

    label = "slowloris" if p["attack"] == "slowloris" else "lordas"
    # marcos das fases (offsets relativos a t0): ataque comeca apos o baseline
    # e termina apos attack_dur. A fase de recuperacao (depois de attack_end)
    # recebe rotulo proprio "recovery" para nao ser confundida com trafego benigno.
    attack_start = p["benign"]
    attack_end = p["benign"] + p["attack_dur"]
    rows = extract_windows(pkts, conn_open, conn_close, legit_log, infra_samples,
                           t0, t_end, p["window_seconds"], attack_label=label,
                           attack_start=attack_start, attack_end=attack_end,
                           recovery_label="recovery")
    out_csv = os.path.join(p["outdir"], f"dataset_{label}.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FEATURE_ORDER)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[orq] dataset gravado: {out_csv} ({len(rows)} janelas)")
    return rows


def main():
    ap = argparse.ArgumentParser(description="Orquestrador Docker LDoS (cenario unico).")
    ap.add_argument("--attack", default="slowloris", choices=["slowloris", "lordas"])
    ap.add_argument("--outdir", default="docker_run")
    ap.add_argument("--benign", type=float, default=15)
    ap.add_argument("--attack-dur", type=float, default=40)
    ap.add_argument("--recovery", type=float, default=15)
    ap.add_argument("--capacity", type=int, default=30)
    ap.add_argument("--lam", type=float, default=20)
    ap.add_argument("--legit-src-ips", type=int, default=16)
    ap.add_argument("--service-work", type=int, default=200000)
    ap.add_argument("--conn-mem-kb", type=int, default=256)
    ap.add_argument("--ts-mean", type=float, default=0.2)
    ap.add_argument("--window-seconds", type=float, default=1.0)
    # slowloris
    ap.add_argument("--n-conns", type=int, default=60)
    ap.add_argument("--delta", type=float, default=2.0)
    ap.add_argument("--t-k", type=float, default=8.0)
    # lordas
    ap.add_argument("--t-ontime", type=float, default=0.01)
    ap.add_argument("--t-offtime", type=float, default=0.02)
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    p = vars(args)
    try:
        run_scenario(p)
    finally:
        cleanup()
        print("[orq] containers removidos.")


if __name__ == "__main__":
    main()