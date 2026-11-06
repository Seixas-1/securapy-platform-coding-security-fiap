# SecuraPy Platform — SIEM como Plataforma de Segurança

Trabalho Final (GS) — **Coding for Security** (prof. Fabio Bara) — FIAP
Evolução do SecuraPy (MVP do 1º semestre) para uma plataforma completa:
persistência, Machine Learning, API REST, dashboard web e assistente LLM.

## Integrantes

| Nome | RM | Responsabilidade |
|------|-----|-----------------|
| Enzo Parada Seixas | 572294 | Núcleo + Persistência — Módulo A (`core/`, reaproveitado/completado do 1º semestre) e Módulo B (`db/`, MongoDB + MySQL) |
| João Iudi | 573667 | Machine Learning — Módulo C (`ml/`: features, treino, validação cruzada, classificação, Isolation Forest) |
| João Pedro Ribeiro | 570090 | API + Docker — Módulo D (`api/`, Flask + JWT) e Módulo F (Dockerfile, docker-compose, verificação via SDK) |
| Guilherme Reis | 573724 | Web + LLM — Módulo E (`web/`, dashboard e segurança) e Módulo G (`ia/`, assistente LLM com fallback) |

> **Isto é uma sugestão** (segue a divisão de 4 pessoas do enunciado da GS,
> seção 7). Ajustem para refletir quem realmente apresentou cada parte (ver
> seção 6.4 — "cada integrante apresenta a parte que contribuiu").

## Descrição

O SecuraPy Platform recebe logs de autenticação, firewall e acesso web,
normaliza os eventos, aplica um motor de regras configurável e um detector
de anomalias (brute force, port scan, blacklist). Eventos e alertas são
persistidos no **MongoDB**; usuários/operadores da plataforma (com controle
de acesso) ficam no **MySQL**. Um classificador de **Machine Learning**
(scikit-learn, `Pipeline` com `StandardScaler`) pontua o risco de cada IP
suspeito para priorizar a triagem, complementando o motor de regras fixas.

Tudo isso é exposto por uma **API REST** (Flask, autenticação JWT) e por um
**dashboard web** com login de operador, defesa contra XSS (Jinja2) e
headers de segurança. Um **assistente com LLM** (com fallback determinístico
por regras quando não há chave de API) explica alertas em linguagem natural.
Alertas críticos continuam sendo transmitidos em tempo real pelo servidor
de alertas TCP (herdado do 1º semestre) para consoles conectados.

## O que foi reaproveitado do 1º semestre

O núcleo (`core/`) é a base construída na GS do 1º semestre
(`coletor.py`, `relatorios.py` já estavam implementados; `regras.py`,
`detector.py`, `enriquecimento.py` e o servidor/cliente de alertas TCP
(`alertas/`) ainda eram apenas o esqueleto da disciplina e foram
**completados agora**, seguindo fielmente as docstrings/testes originais).
O comportamento foi validado contra os 155 testes automatizados herdados
(`testes/`) e contra os cenários de teste A1–A4 do enunciado da GS.

## Arquitetura

```
securaPy_platform/
├── core/            # Núcleo (1º sem, reaproveitado/completado): coletor, regras, detector, enriquecimento, relatorios
├── alertas/         # Servidor/cliente TCP de alertas em tempo real (1º sem)
├── db/              # Persistência: mongo_repo.py, mysql_repo.py, migrar.py
├── ml/              # Machine Learning: features, treinar, classificar (+ Isolation Forest)
├── api/             # API REST Flask + autenticação JWT
├── ia/              # Assistente LLM com fallback por regras
├── web/templates/   # Dashboard HTML (Jinja2, escape automático)
├── logs/            # Logs de teste (auth.log, firewall.log, web_access.log)
├── config/regras.json
├── scripts/         # Inicialização do banco, verificação Docker, relatório de exemplo
├── testes/          # Suíte pytest herdada do núcleo (155 testes)
├── saida/           # Relatórios exportados
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Como executar (com Docker)

```bash
cp .env.example .env
# edite o .env e troque TODOS os valores de exemplo
```

```bash
docker compose up -d --build
```

```bash
docker compose exec api python -m scripts.inicializar_banco
docker compose exec api python -m db.migrar
```

A API/dashboard fica em `http://localhost:5000`. Login com o
`ADMIN_EMAIL`/`ADMIN_PASSWORD` definidos no `.env`.

Verificar se os 3 containers (api, mongo, mysql) subiram corretamente:

```bash
python -m scripts.verificar_docker
```

## Como executar sem Docker (desenvolvimento)

```bash
pip install -r requirements.txt
cp .env.example .env     # edite os valores, apontando MONGO_HOST/MYSQL_HOST para localhost
python -m ml.treinar               # treina o modelo de ML (gera ml/modelo.pkl)
python -m scripts.inicializar_banco
python -m db.migrar
python -m api.app
```

## Rodando os testes

```bash
pip install -r requirements.txt
python -m pytest testes/ -v
```

### Resultado dos testes

```
155 passed in 0.69s
```

(suíte do núcleo herdada do 1º semestre, com os imports adaptados para a
nova estrutura de pacotes `core`/`alertas`)

## Fluxo ponta a ponta (para a demonstração em vídeo)

1. `docker compose up -d --build` — sobe API + MongoDB + MySQL.
2. `POST /api/analisar` (com token) — processa os logs, roda regras +
   detector + ML, persiste no MongoDB.
3. Dashboard web (`/dashboard`) — resumo geral, alertas por severidade,
   top 10 IPs.
4. Busca por IP no dashboard — eventos, alertas, geolocalização e
   explicação do assistente LLM/fallback.
5. `python -m alertas.servidor_alertas` + dois consoles
   `python -m alertas.cliente_alertas` — alerta crítico transmitido em
   tempo real para ambos.

## Variáveis de ambiente

Veja `.env.example`. **Nenhuma credencial é hardcoded no código** — tudo
vem de variável de ambiente (`.env`, nunca commitado).

## Funcionalidades bônus implementadas

- [x] Detecção de anomalias com Isolation Forest (`ml/classificar.py::detectar_anomalias`)
- [x] Autenticação JWT completa (geração e verificação) na API (`api/auth.py`)
- [x] Testes automatizados (pytest) para os módulos do núcleo (155 testes)
- [ ] Correlação temporal (brute force por janela de tempo)

## Demonstração em vídeo

[Link do vídeo enviado pelo Teams]
