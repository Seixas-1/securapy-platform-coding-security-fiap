# Checklist da Equipe — SecuraPy Platform

Passo a passo do que cada integrante precisa fazer antes de gravar o vídeo da GS.
Repositório: https://github.com/Seixas-1/securapy-platform-coding-security-fiap

> A fala de cada um já está pronta em [ROTEIRO_VIDEO.md](ROTEIRO_VIDEO.md) — este
> arquivo é só o "como se preparar", passo a passo.

---

## Passo 0 — igual para todo mundo (fazer primeiro)

1. **Instalar o Docker Desktop**, se ainda não tiver:
   - Baixe em https://www.docker.com/products/docker-desktop/
   - Rode o instalador. Se ele pedir pra escolher entre "Per-user installation" e
     "All-users installation", escolha **All-users** (o per-user falha se o
     Windows não tiver o recurso "Virtual Machine Platform" ativado — o
     all-users ativa isso pra você, só pede a senha de admin).
   - Se pedir pra reiniciar o Windows, reinicie.
   - Abra o Docker Desktop e espere o ícone ficar verde ("Engine running"). Se
     ele reclamar de kernel do WSL2, rode no PowerShell: `wsl --update`, depois
     abra o Docker Desktop de novo.

2. **Clonar o repositório:**
   ```bash
   git clone https://github.com/Seixas-1/securapy-platform-coding-security-fiap.git
   cd securapy-platform-coding-security-fiap
   ```

3. **Criar o seu `.env`** (nunca usar o `.env` de outra pessoa, nunca commitar o seu):
   ```bash
   cp .env.example .env
   ```
   Abra o `.env` e troque todos os valores de exemplo por senhas suas (pode
   inventar, é só pra rodar local). Preencha `ADMIN_EMAIL` e `ADMIN_PASSWORD`
   com algo que você vai lembrar — é o login que você vai usar no dashboard.

4. **Subir os containers:**
   ```bash
   docker compose up -d --build
   ```
   Pode demorar alguns minutos na primeira vez (baixa as imagens do Mongo e do MySQL).

5. **Inicializar o banco e carregar os dados de teste:**
   ```bash
   docker compose exec api python -m scripts.inicializar_banco
   docker compose exec api python -m db.migrar --limpar
   ```

6. **Conferir que subiu tudo certo:**
   ```bash
   pip install docker
   python -m scripts.verificar_docker
   ```
   Tem que aparecer os 3 containers como `running`.

7. Abra `http://localhost:5000` no navegador e entre com o `ADMIN_EMAIL`/`ADMIN_PASSWORD` que você colocou no `.env`. Se o dashboard aparecer com "Total de eventos: 58", deu tudo certo.

---

## João Iudi — Módulo A + B + C (Núcleo, Persistência, Machine Learning)

**O que ler** (nessa ordem, pra entender a dependência entre os módulos):

1. `core/coletor.py` — lê os 3 logs (`auth.log`, `firewall.log`, `web_access.log`) e normaliza em eventos.
2. `core/regras.py` — carrega `config/regras.json` (5 regras) e gera alertas com severidade.
3. `core/detector.py` — detecta força bruta (≥5 falhas), varredura de portas (≥3 portas) e cruza com a blacklist.
4. `core/enriquecimento.py` — classifica IP privado/público e consulta geolocalização.
5. `db/mongo_repo.py` — onde eventos e alertas são salvos (MongoDB).
6. `db/mysql_repo.py` — onde ficam os usuários/operadores (MySQL), com senha em hash.
7. `ml/features.py` → `ml/treinar.py` → `ml/classificar.py` — como o modelo de risco é treinado e usado.

**O que rodar e mostrar na tela do vídeo:**

```bash
docker compose up -d --build
python -m scripts.verificar_docker
docker compose exec api python -m scripts.inicializar_banco
docker compose exec api python -m db.migrar --limpar
```

Se quiser mostrar o treino do modelo rodando ao vivo (opcional, já está feito no repo):
```bash
pip install -r requirements.txt
python -m ml.treinar
```
Isso imprime a precisão/recall/F1 da validação cruzada — bom de mostrar na tela.

**Pra confirmar que entendeu o suficiente** pra responder pergunta do professor:
```bash
python -m pytest testes/ -v
```
Os 155 testes validam exatamente os módulos A (coletor/regras/detector/enriquecimento).

**Sua fala:** seção "2. Núcleo, Persistência e Machine Learning" do [ROTEIRO_VIDEO.md](ROTEIRO_VIDEO.md). Ensaie antes de gravar.

---

## João Pedro Ribeiro — Módulo D + F (API REST, Docker)

**O que ler:**

1. `api/app.py` — todas as rotas da API (eventos, alertas, analisar, ip).
2. `api/auth.py` — como o token JWT é gerado e verificado.
3. `Dockerfile` — como a aplicação é empacotada.
4. `docker-compose.yml` — os 3 serviços (api, mongo, mysql) e como se conectam.
5. `scripts/verificar_docker.py` — o script que confere os containers.

**O que testar antes de gravar** (deixe um bloco de notas ou o Postman pronto com esses comandos, pra não digitar tudo ao vivo):

```bash
# 1. Login — pega o token
curl -X POST http://localhost:5000/api/login -H "Content-Type: application/json" \
  -d "{\"email\":\"SEU_ADMIN_EMAIL\",\"senha\":\"SUA_ADMIN_PASSWORD\"}"

# 2. Tentar criar alerta SEM token (deve dar 401)
curl -X POST http://localhost:5000/api/alertas -H "Content-Type: application/json" -d "{}"

# 3. Rodar a análise completa COM o token
curl -X POST http://localhost:5000/api/analisar -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" -d "{\"pasta_logs\":\"/app/logs\"}"

# 4. Listar eventos com filtro e paginação
curl "http://localhost:5000/api/eventos?fonte=auth&pagina=1&tamanho=5"

# 5. Buscar um IP (dados completos: eventos + alertas + geo + score)
curl "http://localhost:5000/api/ip/185.220.101.1"

# 6. IP mal formatado (deve dar 400, não quebrar)
curl "http://localhost:5000/api/ip/999.999.999.999"
```

Se preferir usar o Postman em vez do terminal, monte uma collection com essas
6 chamadas — fica mais visual pro vídeo.

**Sua fala:** seção "3. API REST e Docker" do [ROTEIRO_VIDEO.md](ROTEIRO_VIDEO.md).

---

## Guilherme Reis — Módulo E + G (Dashboard, Assistente LLM) + teste final + encerramento

Você é quem fecha o vídeo com o teste ponta a ponta — combine com o grupo o
horário certo, porque sua parte depende de tudo que os outros dois já
mostraram estar funcionando.

**O que ler:**

1. `web/templates/login.html`, `dashboard.html`, `busca_ip.html`.
2. As rotas de dashboard/login dentro de `api/app.py` (procure por `@app.get("/dashboard")`, `@app.post("/login")`).
3. `ia/assistente.py` — como funciona a classificação por LLM e o fallback por regras.

**O que testar antes de gravar:**

1. **Login genérico:** entre em `http://localhost:5000/login` com a senha errada e com um email que não existe — confirme que a mensagem de erro é a mesma nos dois casos ("Credenciais inválidas").
2. **XSS:** peça pro João Pedro te passar um token, ou gere o seu, e crie um alerta de teste:
   ```bash
   curl -X POST http://localhost:5000/api/alertas -H "Authorization: Bearer SEU_TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"ip\":\"6.6.6.6\",\"severidade\":\"ALTA\",\"descricao\":\"<script>alert(1)</script>\",\"regra_nome\":\"Teste XSS\"}"
   ```
   Depois busque o IP `6.6.6.6` no dashboard e confirme que o texto aparece
   literalmente na tela (`&lt;script&gt;...`), sem executar.
3. **Headers de segurança:** no navegador, abra as Ferramentas do Desenvolvedor
   (F12) → aba Network → clique em qualquer requisição → confira que aparecem
   `X-Content-Type-Options`, `X-Frame-Options` e `Content-Security-Policy`.
4. **Assistente de IA:** busque um IP com alerta (ex: `185.220.101.1`) no
   dashboard e veja a explicação aparecendo. Sem `OPENAI_API_KEY` configurada
   no `.env`, ele usa o fallback por regras — e tudo bem, é esperado.
5. **Servidor de alertas em tempo real** — abra 3 terminais:
   ```bash
   # Terminal 1 (servidor)
   python -m alertas.servidor_alertas

   # Terminal 2 e 3 (dois clientes)
   python -m alertas.cliente_alertas
   ```
   Digite `/status` em um dos clientes pra confirmar que o servidor vê os 2 conectados.

6. **Ensaie o teste ponta a ponta inteiro pelo menos uma vez antes de gravar de
   verdade:** `docker compose down` (zera tudo) → `docker compose up -d --build`
   → `inicializar_banco` → `migrar --limpar` → `/api/analisar` → dashboard →
   busca de IP → servidor + 2 clientes recebendo um alerta. Isso evita
   surpresa na hora de gravar.

**Sua fala:** seção "4. Dashboard, Assistente de IA e Teste Ponta a Ponta" do
[ROTEIRO_VIDEO.md](ROTEIRO_VIDEO.md) — inclui o fechamento do vídeo.

---

## Depois de gravar

- [ ] Subir o vídeo no Teams (conforme pede o enunciado da GS).
- [ ] Conferir se o link do GitHub está acessível pra quem for avaliar.
- [ ] Atualizar a linha "Demonstração em vídeo" no final do `README.md` com o link do vídeo.
