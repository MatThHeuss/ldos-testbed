# Testbed de ataques Low-Rate DoS — geração de dataset rotulado

Implementação de três ataques **Low-Rate DoS (LDoS)** de categorias distintas —
**Slowloris** (Slow DoS), **Shrew** (ataque à camada de transporte / QoS) e
**LoRDAS** (ataque à fila de serviço de aplicação) — acompanhada de um extrator de
características por janela temporal comum aos três, para a construção de um dataset
rotulado destinado ao estudo de detecção de ataques LDoS.

Cada ataque possui seu próprio orquestrador, mas todos passam pelo mesmo pipeline de
extração (`features.extract_windows(...)`), que produz, para cada janela de tempo,
um conjunto de características de rede acompanhado, quando aplicável, de
características de infraestrutura do servidor e de indicadores de impacto no serviço.
Isso permite consolidar as saídas dos três ataques em um único dataset com cabeçalho
uniforme.

> **Escopo e uso responsável.** Este material destina-se estritamente a fins
> educacionais e de pesquisa. Todo o tráfego dos experimentos ocorre em ambiente
> isolado (loopback, `127.0.0.1`, ou containers em um único host); os atacantes
> recusam alvos fora de loopback. Não utilize este código contra sistemas de
> terceiros.

---

## Arquiteturas de execução: aplicação vs. transporte

Uma característica central do projeto é que os três ataques **não** são reproduzidos
no mesmo tipo de ambiente, e isso reflete a natureza de cada categoria:

- **Slowloris e LoRDAS** atuam na **camada de aplicação** e são executados em um
  ambiente **containerizado (Docker)**, contra um servidor de aplicação real. Nesse
  caso, além das características de rede, são coletadas **características de
  infraestrutura reais** do servidor (uso de CPU, memória e ocupação do *pool* de
  atendimento).

- **Shrew** atua na **camada de transporte** (congestiona o mecanismo de retransmissão
  do TCP) e é reproduzido por um **simulador determinístico** da dinâmica de RTO. Como
  o ataque não interage com o servidor de aplicação, **as características de
  infraestrutura não se aplicam às amostras do Shrew e permanecem vazias** no dataset.
  Essa ausência é uma propriedade fiel do ataque, e **não** um dado faltante a ser
  imputado.

Quem for utilizar o dataset deve considerar essa assimetria na seleção de
características (ver a seção *Uso do dataset*).

---

## Requisitos

```bash
pip install -r requirements.txt   # pyyaml, psutil, matplotlib
```

- **Python 3** (testado em ambiente `venv`).
- Para o caminho consolidado (Docker), é necessário ter o **Docker** instalado e
  utilizável sem `sudo`.

---

## Estrutura do dataset

Cada linha corresponde a uma **janela temporal de 1 s** rotulada. As colunas
agrupam-se em quatro conjuntos:

- **Características de rede** (13): `pkt_count`, `byte_count`, `active_conns_mean`,
  `src_ip_entropy`, `src_port_entropy`, `distinct_src_ips`, `distinct_src_ports`,
  `iat_mean`, `iat_var`, `conn_duration_mean`, `syn_ratio`, `http_incomplete_count`,
  `pkt_size_mean`.
- **Características de infraestrutura** (3): `cpu_pct`, `mem_mib`, `httpd_procs`
  (ocupação do *pool*). Vazias para o Shrew.
- **Indicadores de impacto no serviço** (3): `availability_A` (taxa de sucesso das
  requisições), `rt_mean` (tempo médio de resposta), `refused_rate`. Aplicáveis aos
  ataques de aplicação.
- **Metadados de rastreabilidade**: `label` (`benign`, `slowloris`, `shrew`,
  `lordas`, `recovery`), `scenario_attack`, `scenario_param`, `scenario_value`,
  `scenario_rep`, `window_start`, `window_end`.

> As colunas `attacker_pkts`, `legit_pkts` e `containers_N` acompanham cada amostra
> para fins de análise e rastreabilidade, mas **não devem ser usadas como
> características preditoras** (ver *Uso do dataset*).

O dataset consolidado reúne **7 212 janelas**, provenientes de **102 execuções**
independentes (42 do Slowloris, 36 do LoRDAS e 24 do Shrew) e **50 configurações
paramétricas** distintas, cobrindo as três fases de cada execução (*baseline*,
ataque e recuperação).

---

## Como gerar o dataset

O dataset final é construído em três etapas: (1) a varredura Docker dos ataques de
aplicação, que produz o consolidado base; (2) a varredura do Shrew pelo simulador; e
(3) a integração das saídas em um único arquivo.

### 1. Ataques de aplicação (Slowloris e LoRDAS) — varredura Docker

```bash
# construir a imagem do testbed
docker build -t ldos-testbed -f docker/Dockerfile .

# varredura dos ataques de aplicação -> consolidado base
python docker/sweep.py --outdir sweep_full --repeats 3 \
    --benign 15 --attack-dur 40 --recovery 10
```

Isso gera `sweep_full/dataset_ldos_completo.csv`, contendo as janelas do Slowloris e
do LoRDAS já rotuladas por fase (`benign` / ataque / `recovery`), com as
características de infraestrutura reais medidas via `docker stats`.

Para uma validação rápida da mecânica, sem a varredura completa:

```bash
python docker/sweep.py --minimal --outdir sweep_min
```

### 2. Ataque Shrew — simulação

```bash
python run_shrew_grid.py --sweep grid --outdir shrew_grid \
    --figdir shrew_grid/figuras --repeats 1 --reference-tag D0.2__T1.0
```

A varredura do Shrew percorre uma **malha de *duty cycle* (D) e período (T)**, com a
duração do pulso derivada por `l = D · T`. Por ser um modelo determinístico, cada
configuração produz um resultado único e **não são usadas repetições** (`--repeats 1`).
São geradas 24 configurações; a saída inclui `shrew_grid/results_shrew.csv` (um
cenário por linha) e um `dataset_D<d>__T<t>__l<l>.csv` por configuração.

### 3. Integração no dataset final

O `sweep.py` produz os ataques de aplicação e o `run_shrew_grid.py` produz o Shrew em
arquivos separados, pois rodam em ambientes distintos (Docker e simulação). A etapa
final costura os dois em um único arquivo. O script de integração **substitui** as
janelas do Shrew no consolidado pelas da malha e preserva as janelas de aplicação:

```bash
python integra_shrew_grid.py \
    --shrew-dir shrew_grid \
    --consolidated sweep_full/dataset_ldos_completo.csv \
    --out dataset_ldos_completo.csv
```

O arquivo `dataset_ldos_completo.csv` resultante é o dataset final, com as três
categorias e as três fases de cada execução.

> **Rotulagem por fase.** Os scripts de varredura já produzem as janelas com o rótulo
> de fase correto (incluindo `recovery`). O `docker/relabel_recovery.py` existe para
> reprocessar a rotulagem de recuperação em datasets gerados antes dessa correção, e
> **não é necessário** no fluxo acima.


---

## Executar um único ataque (sem consolidar)

Cada orquestrador roda as três fases (**benigno → ataque → recuperação**) e grava um
`dataset_<tag>.csv` com as características rotuladas, além dos CSVs de resultado por
cenário.

```bash
# LoRDAS (parâmetros e modo de varredura vêm do config.yaml)
python run_experiment.py --config config.yaml --outdir results --repeats 3

# Shrew (varredura de período T, de carga l, ou cenário único)
python run_shrew.py --outdir shrew_out --sweep T --repeats 1
# (para a malha bidimensional D×T usada no dataset, ver run_shrew_grid.py acima)

# Slowloris (varredura em N_c, em delta, ou cenário único)
python run_slowloris.py --outdir slow_out --sweep Nc --repeats 3
```

Opções comuns: `--repeats N` (repetições com sementes diferentes, que geram amostras
independentes para os ataques de aplicação) e `--sweep none` (cenário único, sem
varredura).

### Saídas por orquestrador

Os arquivos gravados no `--outdir` variam conforme o ataque:

| Arquivo                 | LoRDAS | Shrew | Slowloris | Conteúdo                                              |
|-------------------------|:------:|:-----:|:---------:|------------------------------------------------------|
| `dataset_<tag>.csv`     |   ✓    |   ✓   |     ✓     | características por janela, rotuladas — a base para ML |
| `results.csv`           |   ✓    |       |           | um cenário por linha (parâmetros + métricas A, C, O)  |
| `results_shrew.csv`     |        |   ✓   |           | um cenário por linha (ρ por fase, taxa média, etc.)   |
| `results_slowloris.csv` |        |       |     ✓     | um cenário por linha (parâmetros + métricas de impacto) |
| `queue_<tag>.csv`       |   ✓    |       |           | série temporal de ocupação da fila e recusas          |
| `packets_<tag>.csv`     |   ✓\*  |       |           | eventos brutos de pacote, para inspeção/depuração     |

\* Gravado pelo LoRDAS quando a opção correspondente de registro de pacotes está
ativada.

As séries de ocupação da fila (`queue_<tag>.csv`) e os eventos de pacote
(`packets_<tag>.csv`) do LoRDAS servem à análise e à geração de figuras (`plots.py`),
e não integram o dataset de características.

---

## Uso do dataset

Ao treinar modelos sobre o dataset, recomenda-se:

- **Remover as colunas de rastreabilidade e as auxiliares** (`scenario_*`,
  `window_*`, `attacker_pkts`, `legit_pkts`, `containers_N`) do conjunto de
  características. Em particular, `scenario_attack` é o próprio rótulo de tipo e
  `attacker_pkts` revela diretamente a presença do atacante — usá-las como
  características constitui vazamento de informação.
- **Particionar por execução**, mantendo todas as janelas de uma mesma execução em um
  único subconjunto (treino ou teste), para evitar a superestimação de desempenho por
  correlação temporal entre janelas contíguas. Os metadados de rastreabilidade
  permitem esse agrupamento.
- **Tratar as características de infraestrutura ausentes no Shrew** restringindo-se às
  características de rede (comuns às três categorias) ou empregando modelos que lidam
  nativamente com valores ausentes. **Não imputar** valores, pois a ausência é uma
  propriedade real do ataque.

---

## Estrutura do projeto

| Arquivo / pasta         | Papel                                                             |
|-------------------------|------------------------------------------------------------------|
| `common.py`             | protocolo, amostragem, pool de IPs, parse da requisição          |
| `capture.py`            | `PktRecord` (formato canônico de pacote) e buffer de captura     |
| `server.py`             | servidor-vítima (fila finita) + ponto de captura                 |
| `attacker.py`           | atacante **LoRDAS** (ON-OFF preditivo)                           |
| `shrew_sim.py`          | simulador do ataque **Shrew** (rajadas periódicas / dinâmica de RTO) |
| `slowloris_attacker.py` | atacante **Slowloris** (conexões incompletas mantidas abertas)   |
| `legit_client.py`       | tráfego legítimo Poisson (mede disponibilidade e tempo de resposta) |
| `infra.py`              | coletor `psutil` + AutoScaler simulado                           |
| `features.py`           | extrator das características por janela (comum aos 3 ataques)     |
| `run_experiment.py`     | orquestrador do LoRDAS                                            |
| `run_shrew.py` / `run_shrew_grid.py` | orquestrador do Shrew (varredura simples / malha D×T) |
| `run_slowloris.py`      | orquestrador do Slowloris                                         |
| `integra_shrew_grid.py` | integra a malha do Shrew ao consolidado (etapa 3 da geração) |
| `integra_slowloris_nc.py` | utilitário para acrescentar novos pontos de varredura de um ataque de aplicação a um dataset já gerado (não faz parte do fluxo padrão) |
| `plots.py`              | geração de figuras a partir dos CSVs das rodadas                 |
| `docker/`               | testbed Docker (imagem, entrypoints, `orchestrator.py`, `sweep.py`, `relabel_recovery.py`) |

---

## Licença

Este projeto é distribuído sob a **licença MIT** — consulte o arquivo
[`LICENSE`](LICENSE). Em resumo, o uso, a modificação e a redistribuição são livres,
desde que mantido o aviso de copyright.

## Como citar

Se este testbed ou o dataset forem úteis em seu trabalho, por favor cite a dissertação
associada:

> [Matheus Alencar]. *[Título da dissertação]*. Dissertação de Mestrado, Programa de
> Pós-Graduação em informática, Universidade de Brasília, Brasília, 2026.

