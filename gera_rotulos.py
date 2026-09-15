"""
gera_rotulos.py — Materializa as colunas de intensidade e de impacto do rotulo
multidimensional no dataset consolidado.

Intensidade (duty cycle D da configuracao):
  - Shrew:     D (primeira parte de scenario_value "D__T")
  - LoRDAS:    t_ontime / (t_ontime + t_offtime), reconstruindo do base quando fixo
  - Slowloris: min(N_c / capacidade, 1)  (saturado em 1)
  - benign / recovery: 0

Impacto (grau de degradacao do servico):
  - Slowloris / LoRDAS: D(t) da Eq. de degradacao de SLA, janela 10s,
    limiares do baseline de cada execucao; 0 fora do ataque
  - Shrew: 1 - rho_attack (degradacao de throughput) da config, nas janelas de ataque; 0 fora
"""
import csv, re, sys, statistics as st
from collections import defaultdict

RT_MAX = 10.0
BASE = {
    'slowloris': {'capacity':30, 'n_conns':60, 'delta':2.0, 't_k':8.0},
    'lordas':    {'capacity':8, 'delta':0.005, 't_ontime':0.01, 't_offtime':0.02},
}
def f(x):
    try: return float(x)
    except: return None

def intensidade_config(attack, param, value):
    if attack == 'shrew':
        return round(f(value.split('__')[0]), 4)
    if attack == 'lordas':
        ton = BASE['lordas']['t_ontime']; toff = BASE['lordas']['t_offtime']
        if param == 't_ontime': ton = f(value)
        elif param == 't_offtime': toff = f(value)
        return round(ton/(ton+toff), 4)
    if attack == 'slowloris':
        nc = BASE['slowloris']['n_conns']
        if param == 'n_conns': nc = f(value)
        return round(min(nc/BASE['slowloris']['capacity'], 1.0), 4)
    return ''

def main():
    ds_path, res_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    # rho_attack por config do shrew
    rho_atk = {}
    for r in csv.DictReader(open(res_path)):
        m = re.match(r"D([0-9.]+)__T([0-9.]+)__l([0-9.]+)", r['tag'])
        if m:
            key = f"{float(m.group(1))}__{float(m.group(2))}"
            rho_atk[key] = f(r['rho_attack'])

    rows = list(csv.DictReader(open(ds_path)))
    header = list(rows[0].keys())

    # agrupar por execucao
    execs = defaultdict(list)
    for r in rows:
        execs[(r['scenario_attack'], r['scenario_param'], r['scenario_value'], r['scenario_rep'])].append(r)

    impacto = {}  # id(row) -> valor
    for key, er in execs.items():
        atk = key[0]
        er.sort(key=lambda r: f(r['window_start']))
        if atk == 'shrew':
            ben_end, atk_end = 10, 70
            k = f"{float(key[2].split('__')[0])}__{float(key[2].split('__')[1])}"
            rho = rho_atk.get(k)
            if rho is None:
                print(f"[AVISO] config Shrew '{key[2]}' sem correspondencia em "
                      f"{res_path}; impacto ficara vazio. Verifique se o results_shrew "
                      f"cobre todas as configuracoes do dataset.", file=sys.stderr)
                imp_atk = ''
            else:
                imp_atk = round(1-rho, 4)
            for r in er:
                t = f(r['window_start'])
                impacto[id(r)] = imp_atk if (ben_end <= t < atk_end) else 0.0
        else:
            ben_end, atk_end = 15, 55
            serie = []
            for r in er:
                t = f(r['window_start'])
                wl = [w for w in er if t-9 <= f(w['window_start']) <= t]
                As = [f(w['availability_A']) for w in wl if f(w['availability_A']) is not None]
                RTs = [f(w['rt_mean']) for w in wl if f(w['rt_mean']) is not None]
                A10 = st.mean(As) if As else 0.0
                RT10 = st.mean(RTs) if RTs else None
                serie.append((r, t, A10, RT10))
            A_bl = [A for (r,t,A,RT) in serie if t < ben_end]
            RT_bl = [RT for (r,t,A,RT) in serie if t < ben_end and RT is not None]
            A_sla = st.mean(A_bl)-2*st.pstdev(A_bl) if len(A_bl)>1 else (st.mean(A_bl) if A_bl else 1.0)
            RT_sla = st.mean(RT_bl)+2*st.pstdev(RT_bl) if len(RT_bl)>1 else None
            for (r,t,A,RT) in serie:
                if not (ben_end <= t < atk_end):
                    impacto[id(r)] = 0.0
                elif A == 0:
                    impacto[id(r)] = 1.0
                else:
                    tA = (A_sla-A)/A_sla if A_sla>0 else 0
                    tRT = min((RT-RT_sla)/(RT_MAX-RT_sla),1) if (RT is not None and RT_sla and (RT_MAX-RT_sla)>0) else 0
                    impacto[id(r)] = round(max(tA,tRT,0),4)

    new_header = header + ['intensidade', 'impacto']
    with open(out_path, 'w', newline='') as fout:
        w = csv.DictWriter(fout, fieldnames=new_header)
        w.writeheader()
        for r in rows:
            r2 = dict(r)
            # intensidade = duty cycle da config apenas na fase de ataque;
            # 0 nas fases benign e recovery (sem ataque ativo)
            if r['label'] in ('benign', 'recovery'):
                r2['intensidade'] = 0.0
            else:
                r2['intensidade'] = intensidade_config(r['scenario_attack'], r['scenario_param'], r['scenario_value'])
            r2['impacto'] = impacto[id(r)]
            w.writerow(r2)
    print(f"gravado {out_path} com {len(rows)} linhas, {len(new_header)} colunas")

if __name__ == '__main__':
    main()