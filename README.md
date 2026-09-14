# Testbed de ataques Low-Rate DoS — geração de dataset rotulado

Implementação de três ataques **Low-Rate DoS contra servidores de aplicação** —
**LoRDAS**, **Shrew** e **Slowloris** — com um extrator de features por janela
comum aos três, para montar um dataset rotulado de detecção.

Cada ataque tem seu orquestrador, mas todos passam pelo mesmo pipeline de
`features.extract_windows(...)`, produzindo linhas com **as mesmas 20 features**
por janela temporal e um rótulo (`benign`, `lordas`, `shrew` ou `slowloris`). Isso
permite consolidar as saídas dos três ataques em um único dataset.

> **Escopo.** Uso estritamente educacional e de pesquisa. No simulador todo o
> tráfego ocorre em `127.0.0.1`; o atacante recusa alvos fora de loopback salvo
> autorização explícita, e apenas contra hosts próprios em ambiente isolado.

---

## Requisitos

```bash
pip install -r requirements.txt   # pyyaml, psutil, matplotlib (Python 3.12)
```

Para o caminho Docker (dataset consolidado), é preciso Docker instalado e usável
sem `sudo`.

---

## Como executar cada ataque (simulador em loopback)

Cada comando roda as três fases (**benigno → ataque → recuperação**) e grava um
`dataset_<tag>.csv` com as 20 features rotuladas, além dos CSVs de resultado.

```bash
# LoRDAS (cenário único ou varredura conforme config.yaml)
python run_experiment.py --config config.yaml --outdir results --repeats 5

# Shrew (varredura OFAT no período T ou na carga l)
python run_shrew.py --outdir shrew_out --sweep T --repeats 3

# Slowloris (varredura em N_c — nº de conexões — ou no delta)
python run_slowloris.py --outdir slow_out --sweep Nc --repeats 3
```

Opções úteis comuns: `--repeats N` (repetições com sementes diferentes, dão
amostras independentes para o dataset), `--sweep none` (cenário único, sem
varredura). Para o LoRDAS, os parâmetros e o modo de varredura (`ofat`/`grid`)
vêm do `config.yaml` (ou `config_oficial.yaml`, já pronto para as rodadas OFAT
com Δ, t_on e Var).

### Saídas de cada rodada (no `--outdir`)

| Arquivo                | Conteúdo                                                        |
|------------------------|----------------------------------------------------------------|
| `dataset_<tag>.csv`    | **as 20 features por janela, rotuladas** — o dataset de ML      |
| `results*.csv`         | um cenário por linha (parâmetros + métricas de impacto A, C, …) |
| `queue_<tag>.csv`      | série temporal de ocupação da fila e recusas (fora do dataset)  |
| `packets_<tag>.csv`    | eventos brutos de pacote, para inspeção/depuração               |

---

## Gerar o dataset consolidado dos 3 ataques

O dataset combinado (`dataset_ldos_3ataques_*.csv`) reúne as janelas dos três
ataques com colunas de rastreabilidade (`scenario_attack`, `scenario_param`,
`scenario_value`, `scenario_rep`). Ele é produzido pela varredura no **testbed
Docker**, que mede CPU/memória reais via `docker stats`:

```bash
# 1. construir a imagem única do testbed
docker build -t ldos-testbed -f docker/Dockerfile .

# 2. varredura OFAT dos três ataques -> dataset consolidado (escrito incrementalmente)
python docker/sweep.py --outdir sweep_full --repeats 3 --attack-dur 40
#    (validação rápida da mecânica: python docker/sweep.py --minimal --outdir sweep_min)

# 3. resultado: sweep_full/dataset_ldos_3ataques.csv
```

Scripts auxiliares de manutenção do consolidado (sem refazer tudo):

- `docker/relabel_recovery.py` — reetiqueta janelas da fase de recuperação.
- `integra_slowloris_nc.py` / `integra_shrew_grid.py` — **acrescentam** novos
  pontos de varredura (novos N_c do Slowloris, nova grade do Shrew) ao dataset
  consolidado existente, sem duplicar janelas já presentes. Ex.:
  ```bash
  python integra_slowloris_nc.py \
      --novos sweep_nc/dataset_ldos_3ataques.csv \
      --consolidated dataset_ldos_3ataques_v2.csv \
      --out dataset_ldos_3ataques_v3.csv
  ```

> Também é possível montar um dataset combinado apenas com o simulador (sem
> Docker), concatenando os `dataset_<tag>.csv` dos três `run_*.py` — o cabeçalho
> das 20 features é idêntico. Nesse caso, CPU/memória são proxies via `psutil`.

---

## Estrutura do projeto

| Arquivo / pasta        | Papel                                                            |
|------------------------|------------------------------------------------------------------|
| `common.py`            | protocolo, amostragem, pool de IPs, parse da requisição          |
| `capture.py`           | `PktRecord` (formato canônico de pacote) e buffer de captura     |
| `server.py`            | servidor-vítima (fila finita) + ponto de captura                 |
| `attacker.py`          | atacante **LoRDAS** (ON-OFF preditivo)                           |
| `shrew_sim.py`         | simulador do ataque **Shrew** (rajadas periódicas)               |
| `slowloris_attacker.py`| atacante **Slowloris** (conexões incompletas mantidas abertas)   |
| `legit_client.py`      | tráfego legítimo Poisson (mede disponibilidade, tempo de resposta)|
| `infra.py`             | coletor `psutil` + AutoScaler simulado                           |
| `features.py`          | **extrator das 20 features por janela** (comum aos 3 ataques)    |
| `run_experiment.py` / `run_shrew.py` / `run_slowloris.py` | orquestradores dos ataques        |
| `plots.py`             | geração de figuras a partir dos CSVs das rodadas                 |
| `docker/`              | testbed Docker (imagem, entrypoints, `orchestrator.py`, `sweep.py`) |
