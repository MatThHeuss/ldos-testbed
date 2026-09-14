# Testbed LoRDAS (loopback) — geração de dataset rotulado para pesquisa

Implementação fiel do ataque **LoRDAS** (*Low-Rate DoS against Application
Servers*) para simulações locais, **com extração de features por janela** para
montar o dataset de detecção da dissertação. Baseado em:

> J. Maciá-Fernández, J. E. Díaz-Verdejo, P. García-Teodoro, *"Mathematical
> Model for Low-Rate DoS Attacks Against Application Servers"*, IEEE TIFS,
> vol. 4, no. 3, pp. 519–529, 2009.

> **Escopo.** Uso estritamente educacional e de pesquisa. Todo o tráfego ocorre
> em `127.0.0.1`. O atacante **recusa** alvos fora de loopback salvo
> `allow_nonloopback=True`, que só deve ser usado contra hosts próprios e
> autorizados, em ambiente isolado.

---

## Arquitetura

```
 legit_client.py        attacker.py                  server.py  ── captura ──► Capture
 (Poisson, λ,          LoRDAS ON-OFF + replies,     fila finita   (PktRecords normalizados)
  pool de IPs)         estima T_s, pool de IPs      N_s workers          │
        │                     │                     T_s ~ N(m,var)       │
        └───────── loopback ──┴─────────────────────────┘                │
                                                                         ▼
 infra.py (psutil + AutoScaler)  ──amostras CPU/mem/workers/N(t)──►  features.py
                                                                    (janelas → dataset.csv)
        run_experiment.py = orquestra tudo, fase benigna opcional, grava CSVs
```

## Módulos

| Arquivo             | Papel                                                                 |
|---------------------|-----------------------------------------------------------------------|
| `common.py`         | protocolo, amostragem gaussiana, pool de IPs, parse da requisição      |
| `capture.py`        | `PktRecord` (formato canônico de pacote), buffer `Capture`, entropia   |
| `server.py`         | servidor-vítima **+ ponto de captura** (emite PktRecords por conexão)  |
| `attacker.py`       | atacante LoRDAS (ON-OFF preditivo, replies, estimativa de `T_s`)       |
| `legit_client.py`   | tráfego legítimo Poisson (mede `A`, `RT`, recusas)                     |
| `infra.py`          | coletor `psutil` + `AutoScaler` simulado (série `N(t)`)                |
| `features.py`       | **extrator de features por janela** → dataset rotulado                 |
| `run_experiment.py` | orquestrador, varredura, fase benigna, escrita dos CSVs                |
| `plots.py`          | geração de figuras (PDF/PNG) a partir dos CSVs das rodadas             |
| `queue_metrics.py`  | métricas auxiliares de ocupação da fila e recusas (fora do dataset)   |

---

## As 20 features do dataset (arquivo `dataset_<tag>.csv`)

> O `dataset_<tag>.csv` contém **exatamente estas 20 features**. Métricas de
> **ocupação da fila** e **recusas** (pedidas para reporte) NÃO entram aqui —
> ficam em `results.csv` (agregado) e `queue_<tag>.csv` (série temporal), via
> `queue_metrics.py`.

Uma linha por **janela temporal** (`window_seconds`), com o rótulo
(`benign` / `<label>`). A rotulagem é por presença de tráfego do atacante na
janela — a fase benigna (`attack_start_delay`) gera as janelas `benign`.

| Categoria       | Feature (coluna)        | Fonte na tese         | Como é obtida aqui                                                        |
|-----------------|-------------------------|-----------------------|--------------------------------------------------------------------------|
| **Volume**      | `pkt_count`             | PCAP · Geral          | nº de PktRecords na janela                                                |
|                 | `byte_count`            | PCAP · Geral          | soma de `size` (payload + `header_overhead_bytes`)                        |
|                 | `active_conns_mean`     | PCAP · Slowloris      | concorrência média (integral de sobreposição conexão×janela)             |
| **Distribuição**| `src_ip_entropy`        | PCAP · Geral          | entropia de Shannon dos IPs de origem (entrada)                          |
|                 | `src_port_entropy`      | PCAP · Geral          | entropia das portas de origem (efêmeras reais)                          |
|                 | `distinct_src_ips`      | PCAP · Geral          | nº de IPs de origem distintos                                            |
|                 | `distinct_src_ports`    | PCAP · Slowloris      | nº de portas de origem distintas                                        |
| **Temporalidade**| `iat_mean`             | PCAP · Shrew, LoRDAS  | média do inter-arrival entre chegadas de conexão (SYN)                  |
|                 | `iat_var`               | PCAP · Shrew          | variância do inter-arrival                                               |
|                 | `conn_duration_mean`    | PCAP · Slowloris, LoRDAS | duração média das conexões abertas na janela                         |
| **Protocolo**   | `syn_ratio`             | PCAP · Shrew          | SYN / total de pacotes (ver nota)                                        |
|                 | `http_incomplete_count` | PCAP · Slowloris      | requisições com `HC=0` (Slowloris; 0 para LoRDAS)                        |
|                 | `pkt_size_mean`         | PCAP · Geral          | `byte_count / pkt_count`                                                 |
| **Infra/impacto**| `cpu_pct`              | docker stats · Geral  | `psutil` CPU% do processo do testbed (proxy)                            |
|                 | `mem_pct`               | docker stats · Slowloris, LoRDAS | `psutil` mem% (proxy)                                          |
|                 | `httpd_procs`           | docker exec · Slowloris | nº médio de workers ocupados (proxy de httpd ativos)                 |
|                 | `availability_A`        | Clientes · Geral      | `A = servidas / (servidas+recusadas)` (legítimas na janela)            |
|                 | `rt_mean`               | Clientes · Geral      | tempo médio de resposta das legítimas servidas                          |
|                 | `refused_rate`          | Clientes · Slowloris  | fração de legítimas recusadas                                           |
|                 | `containers_N`          | Auto-scaling · EDoS   | réplicas do `AutoScaler` simulado (série `N(t)`)                        |

Colunas auxiliares (`attacker_pkts`, `legit_pkts`) ajudam na análise; não são
features obrigatórias.

### Notas de fidelidade (declarar na metodologia)
- **IPs de origem em loopback** são todos `127.0.0.1`. A camada de captura
  carimba cada conexão com um **IP lógico** de um pool (`attacker_src_ips`,
  `legit_src_ips`) para emular a topologia distribuída que a feature deve
  detectar. No Docker, esses IPs vêm dos cabeçalhos reais. Efeito visível:
  ataque de origem única ⇒ `src_ip_entropy` baixa (~1 IP) vs. legítimo alto.
- **Portas de origem são reais** (efêmeras, via `getpeername`) — `src_port_entropy`
  e `distinct_src_ports` são fiéis e crescem com a taxa de conexões do ataque.
- **`syn_ratio`** é um proxy de nível de aplicação (SYN/total). Como cada conexão
  é uniforme no LoRDAS, tende a ~constante; torna-se discriminativo com fluxos de
  forma variável (rajadas Shrew, conexões longas Slowloris/`HC=0`).
- **CPU/mem** são proxies via `psutil` (o "serviço" usa `sleep`, então a CPU
  reflete sobretudo o *churn* de conexões das rajadas — ainda assim sobe no ataque).
- **`AutoScaler`** produz `N(t)` como sinal observável mas **não** altera a
  capacidade do servidor (fixa neste testbed). No Docker real as réplicas mudariam
  a capacidade de fato.

---

## Mapeamento parâmetro ↔ artigo

| Config          | Símbolo    | Significado                                          |
|-----------------|------------|------------------------------------------------------|
| `n_workers`     | `N_s`      | threads/processos de serviço                         |
| `queue_size`    | —          | posições totais na fila (`≥ N_s`)                    |
| `ts_mean`       | `T̄_s`     | tempo de serviço médio                               |
| `ts_var`        | `Var`      | **variância** do tempo de serviço                    |
| `delta`         | `Δ`        | intervalo entre mensagens na fase ativa (`1/Δ`)      |
| `t_ontime`      | `t_ontime` | duração da fase ativa                                |
| `t_offtime`     | `t_offtime`| duração da fase inativa (`T_ef = t_on + t_off`)      |
| `rtt_mean/var`  | `RTT`      | atraso ida-e-volta (média / **variância**)           |
| `lam`           | `λ`        | taxa de Poisson do tráfego legítimo                  |
| `sync_mode`     | —          | `freerate` (mira cada instante livre, `τ=T_s/N_s`) ou `period` (`T_ef` literal) |

## Indicadores agregados (`results.csv`)

`C` (prob. de sucesso do cliente), `A` (disponibilidade), `O_eq31_count`
(overhead por período = `floor(t_on/Δ)+1 + (1−P_u)`, Eq. 31 — use para comparar
com a Fig. 9) e `O_rate_ratio` (razão de taxas empírica). Métricas de fila em `results.csv`:
`queue_occ_mean`/`queue_occ_peak` (ocupação média/pico), `queue_full_frac`
(fração de tempo com a fila cheia — vale a identidade `C + queue_full_frac = 1`,
pois há vaga livre se e só se a fila não está cheia) e as contagens de recusa.

---

## Como executar

```bash
pip install pyyaml psutil matplotlib

# cenário único ou varredura (conforme config.yaml):
python run_experiment.py --config config.yaml --outdir results

# só C, sem tráfego legítimo (definição do artigo):
python run_experiment.py --config config.yaml --c-only

# repetições p/ estatística:
python run_experiment.py --config config.yaml --repeats 5

# overrides:
python run_experiment.py --window_seconds 0.5 --attack_start_delay 10 \
                         --attacker_src_ips 50 --duration 60
```

### Desenho da varredura: `sweep_mode`

O `sweep_mode` (em `defaults`) controla como os cenários são gerados:

- **`ofat`** (um fator por vez) — roda um `baseline` e depois varia **um**
  parâmetro de cada vez (os demais no baseline). Cresce **linearmente**
  (`1 + Σ nº de valores`). É a metodologia da Fig. 9 do artigo e gera **uma
  figura de sensibilidade por parâmetro**. Recomendado para as rodadas oficiais.
- **`grid`** (produto cartesiano) — todas as combinações. Cresce
  **multiplicativamente**; use apenas para grades pequenas.

Exemplo: Δ(5) + t_on(5) + Var(5) ⇒ **OFAT = 13 cenários**; **grid = 125**.
Nº total de rodadas = (cenários) × `--repeats`. Prefira **duração curta + mais
repetições**: cada rodada usa semente diferente, o que dá amostras independentes
(melhor para o dataset) e barras de erro nas curvas de sensibilidade.

Config pronto para as oficiais: **`config_oficial.yaml`** (OFAT com Δ, t_on e Var).

```bash
python run_experiment.py --config config_oficial.yaml --outdir oficial \
                         --repeats 5 --plots --figdir oficial/figuras
```

**Acoplamento fila↔workers.** Com `queue_equals_workers: true`, `queue_size` é
forçado a `n_workers` a cada rodada — assim você pode variar `n_workers` sem
deixar a fila menor que o nº de workers. (Se quiser estudar `queue_size` isolado,
deixe `false` e varie `queue_size` com `n_workers` fixo.)

**Cuidado com `sync_mode` na varredura.** No `freerate` (padrão) o período é
`τ = T_s/N_s` e **`t_offtime` é derivado** — variar `t_offtime` não tem efeito.
Nesse modo variam com sentido: `delta`, `t_ontime`, `ts_var`, `n_workers`,
`ts_mean`, `lam`, `rtt_*`. Para variar `t_offtime` (e reportar `T_ef = t_on+t_off`
como no artigo), use `sync_mode: period`.

### Fases: benigno -> ataque -> recuperacao

`attack_start_delay` define a fase benigna (janelas `benign`) e `recovery_seconds`
a fase de recuperacao apos o ataque (atacante para, trafego legitimo continua;
janelas voltam a `benign`). Com um baseline nao saturado (`lambda < N_s/T_s`), a
figura de impacto mostra as tres fases: A~1 -> A~0 -> A~1.

### Gerar as duas classes (benign + ataque)
Defina `attack_start_delay > 0`: roda-se tráfego legítimo puro por N segundos
(janelas `benign`) e então o atacante entra (janelas `<label>`). Um experimento
já produz dataset balanceável para o classificador.

### Reproduzir a sensibilidade do artigo (Fig. 9)
Use `sweep_mode: ofat` e liste os três em `sweep:` (como em `config_oficial.yaml`).
Sai uma figura por parâmetro:
- **Fig. 9(a)** `t_ontime`: `t_on ↑ ⇒ C ↓, A ↓, O ↑`.
- **Fig. 9(b)** `delta`: `Δ ↑ ⇒ C ↑, O ↓`.
- **Fig. 9(c)** `ts_var`: randomizar `T_s` **não** é defesa eficaz (C quase não muda).

## Gráficos (módulo `plots.py`)

As figuras são geradas por código, **lendo os CSVs das rodadas** (fiéis aos
dados — nada é desenhado à mão). Saem em PDF (vetorial, para o LaTeX) e PNG.

```bash
# gerar figuras a partir de um diretorio de resultados:
python plots.py --results-dir results --figdir figuras

# ou automaticamente ao final do experimento:
python run_experiment.py --config config.yaml --plots --figdir figuras

# escolher um cenario especifico p/ as figuras temporais/waveform:
python plots.py --results-dir results --tag t_ontime0.008
```

Figuras produzidas (quando os dados existem):

| Arquivo                        | Fonte              | O que mostra (para a banca)                                        |
|--------------------------------|--------------------|-------------------------------------------------------------------|
| `01_sensibilidade_<param>`     | `results.csv` (varredura) | `C`, `A`, `O` vs. parâmetro — **uma figura por parâmetro** (Fig. 9) |
| `02_tradeoff_A_O`              | `results.csv`      | assinatura *low-rate*: baixo `A` com baixo `O`, agrupado por parâmetro |
| `03_waveform_<tag>`            | `packets_<tag>.csv`| forma de onda ON-OFF (visão geral + zoom nas rajadas)             |
| `04_iat_hist_<tag>`           | `packets_<tag>.csv`| inter-arrival bimodal (LoRDAS) vs. exponencial (Poisson)         |
| `05_impacto_temporal_<tag>`    | `dataset_<tag>.csv`| `A(t)` e recusa com a transição benigno→ataque marcada           |
| `06_edos_infra_<tag>`         | `dataset_<tag>.csv`| CPU, workers httpd e `N(t)` (escalonamento EDoS)                 |
| `10_ocupacao_fila_<tag>`      | `queue_<tag>.csv`  | ocupação da fila saturando na capacidade + recusas por janela    |
| `07_separabilidade_features`   | todos `dataset_*`  | boxplots por classe — separabilidade das features                |
| `08_scatter_features`          | todos `dataset_*`  | dispersão 2D com as classes separadas                            |
| `09_correlacao_features`       | todos `dataset_*`  | heatmap de correlação entre features                             |

O `plots.py` escolhe automaticamente um cenário representativo (rajadas
multi-pacote com silêncio entre elas) para as figuras temporais; a largura e o
*bin* do zoom da forma de onda derivam do período `τ = T_s/N_s` do cenário.
Inclua no LaTeX com `\includegraphics{figuras/05_impacto_temporal_<tag>.pdf}`.

## Saídas

- `results/results.csv` — um cenário por linha (parâmetros + `A`,`C`,`O` e as
  métricas de fila: `queue_occ_mean`, `queue_occ_peak`, `queue_full_frac`,
  `refused_total`/`refused_attacker`/`refused_legit`).
- `results/dataset_<tag>.csv` — **features por janela, rotuladas** (o dataset de ML,
  com exatamente as 20 features).
- `results/queue_<tag>.csv` — **série temporal de ocupação da fila** e recusas por
  janela (`occ_mean`, `occ_peak`, `full_fraction`, `refused`, `accepted`) — métrica
  de reporte, separada do dataset.
- `results/packets_<tag>.csv` — eventos brutos (`time,direction,kind,tag,src_ip,
  src_port,size,is_syn,http_complete,conn_id`) para inspeção/depuração.

---

## Migração para o testbed Docker (mesmo extrator de features)

O `features.extract_windows(...)` consome uma lista de `PktRecord` + logs de
cliente + amostras de infra. Para usar capturas reais:

1. **Captura real**: rode `tcpdump`/`tshark` no bridge Docker e converta cada
   pacote em `PktRecord` (`t, src_ip, src_port, dst_ip, dst_port, size, is_syn,
   tag, conn_id, direction, kind, http_complete`). O `tag`/`conn_id` você deriva
   por IP de origem / 5-tupla. Alimente o mesmo `extract_windows`.
2. **Infra real**: substitua `InfraCollector.sample()` por
   `docker stats --no-stream --format ...` (CPU/mem), `docker exec <c> pgrep -c httpd`
   (processos httpd) e a contagem real de réplicas (`docker ps` / `kubectl get`)
   para `containers_N`.
3. **Ataques reais**: os mesmos rótulos (`benign`, `lordas`, `shrew`, `slowloris`)
   e janelas se aplicam; basta marcar a janela pela ferramenta de ataque ativa.

Assim o pipeline de dataset é idêntico entre o simulador e o ambiente real.

## Limitações
- RTT em loopback é ~µs; `rtt_mean`/`rtt_var` **emulam** rede (não substituem `tc/netem`).
- Escala temporal reduzida (`T_s` de dezenas/centenas de ms) p/ viabilizar muitas
  execuções; as tendências se preservam. O artigo usa `T_s ∈ [1,15] s`.
- Precisão de temporização limitada pelo SO/GIL; prefira execuções mais longas.
