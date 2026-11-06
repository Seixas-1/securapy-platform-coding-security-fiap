# Roteiro do Vídeo — SecuraPy Platform

Roteiro de fala para o vídeo de demonstração da GS (Coding for Security, prof. Fabio Bara).
Duração alvo: **12–18 min**. Dividido pelos 4 integrantes conforme a tabela de responsabilidades do [README.md](README.md).

## Visão geral

| Ordem | Quem | Assunto | Duração sugerida |
|---|---|---|---|
| 1 | Enzo | Abertura / contexto | ~1 min |
| 2 | João Iudi | Núcleo + Persistência + Machine Learning | ~5 min |
| 3 | João Pedro Ribeiro | API REST + Docker | ~4 min |
| 4 | Guilherme Reis | Dashboard + Assistente LLM + teste ponta a ponta + encerramento | ~6 min |

---

## 1. Abertura — Enzo (RM 572294)

> Só o começo, ~1 minuto, sem demonstração técnica.

**O que falar:**

"Oi, somos o grupo [nome do grupo] e esse é o Trabalho Final — a GS de Coding for Security. No primeiro semestre, a gente, como a consultoria CyberShield, entregou pro cliente um MVP do SecuraPy: um SIEM simples em linha de comando que lia logs de autenticação, firewall e acesso web, aplicava regras de detecção e identificava ataques como força bruta, varredura de portas e IPs maliciosos conhecidos.

O cliente aprovou o MVP e pediu mais: queria os dados guardados num banco de verdade, não em memória; uma API pra outros sistemas consultarem; machine learning pra ajudar a priorizar os alertas; um painel web pros analistas; e um assistente de IA pra explicar os eventos em linguagem natural.

Foi isso que a gente construiu: o **SecuraPy Platform**. A gente reaproveitou todo o núcleo do primeiro semestre e construiu seis camadas novas em cima dele. Agora cada um vai mostrar a parte que fez."

*(Passa a palavra pro João Iudi)*

---

## 2. Núcleo, Persistência e Machine Learning — João Iudi (RM 573667)

**O que mostrar na tela, na ordem:**

1. Estrutura de pastas do projeto (`core/`, `db/`, `ml/`, `api/`, `ia/`, `web/`, `alertas/`).
2. Terminal: `docker compose up -d --build` — subindo os 3 containers (API, MongoDB, MySQL).
3. `python -m scripts.verificar_docker` — confirmando os 3 "running".
4. `docker compose exec api python -m scripts.inicializar_banco` — criando tabelas MySQL + índices Mongo.
5. `docker compose exec api python -m db.migrar --limpar` — ingestão dos logs.

**O que falar:**

"Essa parte reaproveita o núcleo do primeiro semestre: `coletor.py`, que lê os três arquivos de log (autenticação, firewall e web) e normaliza tudo num formato de evento padrão; `regras.py`, o motor de regras configurável, que carrega o `regras.json` com 5 regras e classifica a severidade; e `detector.py`, que detecta força bruta (a partir de 5 tentativas falhas), varredura de portas (a partir de 3 portas distintas) e cruza os IPs com uma blacklist conhecida.

No primeiro semestre, só o coletor e os relatórios já estavam prontos — as regras, o detector e o servidor de alertas em tempo real ainda eram só o esqueleto do exercício. Completamos tudo agora e validamos contra os 155 testes automatizados que já existiam.

A diferença pra antes é que agora isso não fica só na memória. Os eventos e alertas vão pro **MongoDB** — aqui, `db/mongo_repo.py` — com índices em IP e timestamp pra consultas rápidas. Os usuários da plataforma (os operadores que vão logar no painel) ficam no **MySQL**, em `db/mysql_repo.py`, com queries sempre parametrizadas contra SQL Injection e senha nunca em texto puro — a gente usa hash PBKDF2.

Rodando a ingestão agora: [mostra o terminal] 58 eventos processados — 23 de autenticação, 17 de firewall, 18 de acesso web — e 31 alertas gerados pelas regras.

A parte de machine learning fica em `ml/`. Em vez de só confiar nas regras fixas, treinamos um classificador — um `Pipeline` do scikit-learn com `StandardScaler` e regressão logística — que aprende a dar uma nota de risco pra cada IP, baseado em quantas falhas de login, quantas portas distintas, se está na blacklist e quantos erros web ele gerou. Validamos com validação cruzada e deu precisão e recall próximos de 100%. O modelo fica salvo com um hash SHA-256, e antes de usar a gente confere se o hash bate — se alguém trocar o arquivo do modelo, o sistema recusa usar.

Como bônus, também tem detecção de anomalias com Isolation Forest, pra achar padrões estranhos que as regras fixas não cobrem."

*(Passa a palavra pro João Pedro)*

---

## 3. API REST e Docker — João Pedro Ribeiro (RM 570090)

**O que mostrar na tela, na ordem:**

1. `POST /api/login` com o usuário admin — recebendo o token JWT.
2. `POST /api/alertas` **sem** token — mostrando o 401.
3. `POST /api/analisar` **com** token — mostrando a resposta com eventos processados, alertas e os scores de ML.
4. `GET /api/eventos?fonte=auth&pagina=1&tamanho=5` e `GET /api/alertas?severidade=critica` — filtros e paginação.
5. `GET /api/ip/185.220.101.1` — eventos + alertas + geolocalização + score, tudo junto.
6. `GET /api/ip/999.999.999.999` — mostrando o 400 de IP inválido.
7. Abrir o `Dockerfile` e o `docker-compose.yml` rapidamente.

**O que falar:**

"Minha parte é a API REST, em `api/app.py`, feita em Flask, e o empacotamento com Docker.

A API expõe tudo que o Iudi mostrou: tem rota pra listar eventos e alertas com filtros e paginação, rota pra buscar um alerta específico pelo id, rota pra criar alerta manualmente, e a rota principal, `/api/analisar`, que roda o pipeline inteiro — coletor, regras, detector e o score de machine learning — e já persiste tudo no banco.

Toda rota de escrita exige autenticação. A gente usa **JWT**: o operador faz login em `/api/login` com email e senha, a API confere no MySQL e devolve um token assinado, que expira em 8 horas. Sem token, ou com token inválido, a API responde 401 — não deixa passar. [mostra o teste sem token]

Rodando `/api/analisar` com o token: [mostra a resposta] — os 58 eventos, os 31 alertas, e pra cada IP suspeito o score de risco do modelo de ML. O `185.220.101.1`, que aparece em força bruta, varredura de portas e blacklist ao mesmo tempo, fica com quase 100% de risco.

A busca por IP junta tudo numa rota só: eventos, alertas, geolocalização (a gente usa a API pública do ipinfo.io, com cache pra não repetir consulta) e o score de ML. E se o IP vier num formato inválido, a API devolve 400 com uma mensagem amigável, não quebra.

Pra garantir que isso roda igual em qualquer máquina, empacotamos tudo com Docker: um `Dockerfile` pra aplicação Python e um `docker-compose.yml` que sobe a API, o MongoDB e o MySQL juntos, na mesma rede. Tem até um script, `scripts/verificar_docker.py`, que usa o SDK do Docker em Python pra confirmar que os três containers estão rodando."

*(Passa a palavra pro Guilherme)*

---

## 4. Dashboard, Assistente de IA e Teste Ponta a Ponta — Guilherme Reis (RM 573724)

**O que mostrar na tela, na ordem:**

1. Login no dashboard (`http://localhost:5000/login`) com senha errada — mostra a mensagem genérica.
2. Login correto — mostra o dashboard com o resumo geral, alertas por severidade e top 10 IPs.
3. Criar um alerta com `<script>alert(1)</script>` na descrição (via `POST /api/alertas`) e mostrar no dashboard que aparece como texto, sem executar.
4. Abrir as ferramentas de desenvolvedor do navegador e mostrar os headers de segurança na resposta.
5. Buscar um IP no dashboard e mostrar a explicação do assistente de IA.
6. **Teste ponta a ponta final:** `docker compose up` do zero → `/api/analisar` → dashboard → busca de IP → score de ML → explicação da IA.
7. Abrir dois terminais com `python -m alertas.cliente_alertas` conectados, e em um terceiro rodar o servidor — mostrar um alerta chegando nos dois ao mesmo tempo.
8. Encerramento.

**O que falar:**

"Minha parte é o painel web e o assistente de inteligência artificial.

O dashboard, em `web/templates/`, é feito com Flask e Jinja2. O login do operador usa uma mensagem de erro **genérica** — 'Credenciais inválidas' — tanto pra senha errada quanto pra usuário que não existe, assim ninguém descobre por tentativa quais emails estão cadastrados na plataforma. [mostra o teste]

Entrando com a conta certa, o painel mostra o resumo geral: total de eventos, alertas por severidade, e o top 10 de IPs mais suspeitos.

Um cuidado importante aqui é a defesa contra XSS. Se um atacante conseguisse injetar um `<script>` numa descrição de alerta, isso não pode executar no navegador de quem está olhando o painel. [mostra o teste] — o texto aparece literalmente na tela, porque o Jinja2 escapa tudo por padrão. Toda resposta da aplicação também sai com headers de segurança: `X-Content-Type-Options`, `X-Frame-Options` e `Content-Security-Policy`. [mostra nos headers]

A outra parte é o assistente de IA, em `ia/assistente.py`. Ele recebe um evento e classifica em NORMAL, SUSPEITO ou CRÍTICO, com uma explicação curta em português — pensa nele como um analista júnior. A chave da API fica numa variável de ambiente, nunca no código, e a temperatura é baixa pra respostas mais consistentes. Se não tiver chave configurada, ou se a resposta da IA vier fora do formato esperado, o sistema cai automaticamente num **fallback por regras** — então a demonstração nunca depende de crédito de API pra funcionar. E mesmo o texto que vem de dentro do log — que pode ter sido forjado por um atacante — é tratado só como dado dentro do prompt, nunca como uma instrução pro modelo seguir.

Pra fechar, vamos fazer o teste ponta a ponta: [sobe tudo do zero com docker compose up, roda a análise pela API, mostra o dashboard atualizado, busca um IP e mostra o score e a explicação da IA].

E por último, os alertas em tempo real — isso vem direto do primeiro semestre. Aqui tem dois consoles conectados no servidor de alertas por socket TCP. [dispara um alerta e mostra chegando nos dois ao mesmo tempo].

Esse foi o SecuraPy Platform — do MVP em linha de comando do primeiro semestre pra uma plataforma completa, com persistência, machine learning, API, painel web e inteligência artificial. Valeu!"

---

## Checklist antes de gravar

- [ ] `.env` preenchido (cada um usa o próprio, nunca commitado).
- [ ] `docker compose up -d --build` rodado com antecedência pra garantir que builda sem erro.
- [ ] `docker compose exec api python -m scripts.inicializar_banco` já rodado (cria o usuário admin).
- [ ] `docker compose exec api python -m db.migrar --limpar` rodado **pouco antes de gravar**, pra começar com dados limpos (58 eventos, 31 alertas — sem duplicata).
- [ ] Terminal com `curl` ou Postman configurado com o token de `/api/login` pronto.
- [ ] Duas janelas de terminal separadas abertas pra rodar `alertas.cliente_alertas` lado a lado.
- [ ] Testar o fluxo inteiro **uma vez sem gravar** antes da gravação de verdade — o teste final da apresentação não pode ser a primeira vez que tudo roda junto.
- [ ] Depois de gravar: subir o vídeo no Teams e colocar o link no `README.md`.
