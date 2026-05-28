"""
CodeFlow Backend — Flask + SQLite
API REST completa para o produto de autofix de código
"""
from flask import Flask, jsonify, request, g
from datetime import datetime, timezone
import sqlite3, os, hashlib, secrets, jwt, json, re, time

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "codeflow-dev-secret-change-in-prod")
app.config["DATABASE"] = os.environ.get("DATABASE", "codeflow.db")
JWT_EXPIRY = 60 * 60 * 24 * 7  # 7 days

# ─── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        email       TEXT    UNIQUE NOT NULL,
        name        TEXT    NOT NULL,
        password    TEXT    NOT NULL,
        plan        TEXT    NOT NULL DEFAULT 'starter',
        created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
        github_token TEXT
    );

    CREATE TABLE IF NOT EXISTS repos (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id),
        name        TEXT    NOT NULL,
        full_name   TEXT    NOT NULL,
        language    TEXT,
        framework   TEXT,
        github_id   TEXT,
        connected   INTEGER NOT NULL DEFAULT 1,
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id     INTEGER NOT NULL REFERENCES repos(id),
        status      TEXT    NOT NULL DEFAULT 'pending',
        total_issues INTEGER DEFAULT 0,
        high_issues  INTEGER DEFAULT 0,
        med_issues   INTEGER DEFAULT 0,
        low_issues   INTEGER DEFAULT 0,
        score        INTEGER DEFAULT 0,
        started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
        finished_at TEXT
    );

    CREATE TABLE IF NOT EXISTS issues (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER NOT NULL REFERENCES scans(id),
        repo_id     INTEGER NOT NULL REFERENCES repos(id),
        severity    TEXT    NOT NULL,
        title       TEXT    NOT NULL,
        description TEXT,
        file_path   TEXT,
        line_number INTEGER,
        rule        TEXT,
        fix_diff    TEXT,
        fix_explanation TEXT,
        status      TEXT    NOT NULL DEFAULT 'open',
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS pull_requests (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_id     INTEGER NOT NULL REFERENCES repos(id),
        issue_id    INTEGER REFERENCES issues(id),
        pr_number   INTEGER,
        title       TEXT,
        url         TEXT,
        status      TEXT    NOT NULL DEFAULT 'open',
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS team_members (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id),
        name        TEXT    NOT NULL,
        email       TEXT    NOT NULL,
        github_login TEXT,
        role        TEXT    DEFAULT 'developer',
        added_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    """)
    db.commit()

# ─── AUTH ──────────────────────────────────────────────────────────────────────

def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()

def make_token(user_id):
    payload = {"sub": user_id, "exp": int(time.time()) + JWT_EXPIRY, "iat": int(time.time())}
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return error("Token ausente", 401)
        token = auth.split(" ", 1)[1]
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            g.user_id = data["sub"]
        except jwt.ExpiredSignatureError:
            return error("Token expirado", 401)
        except Exception:
            return error("Token inválido", 401)
        return f(*args, **kwargs)
    return wrapper

# ─── HELPERS ───────────────────────────────────────────────────────────────────

def ok(data=None, status=200, **kwargs):
    body = {"success": True}
    if data is not None: body["data"] = data
    body.update(kwargs)
    return jsonify(body), status

def error(msg, status=400):
    return jsonify({"success": False, "error": msg}), status

def row_to_dict(row):
    return dict(row) if row else None

def rows_to_list(rows):
    return [dict(r) for r in rows]

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = CORS_ORIGINS
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    return resp

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        return "", 204

# ─── ANALYSIS ENGINE ──────────────────────────────────────────────────────────

RULES = [
    {
        "rule": "undefined-variable",
        "severity": "high",
        "title": "Variável não definida no escopo",
        "description": "Uma variável é usada sem ser definida no escopo atual. Causa NameError em produção.",
        "pattern": r'\b(cep|user|data|result|response)\b(?!\s*=)',
        "languages": ["python"],
    },
    {
        "rule": "unhandled-http-error",
        "severity": "high",
        "title": "HTTP error não tratado",
        "description": "requests.get() sem raise_for_status(). Erros 4xx/5xx passam silenciosamente.",
        "pattern": r'requests\.(get|post|put|delete)\(',
        "languages": ["python"],
    },
    {
        "rule": "sql-no-params",
        "severity": "high",
        "title": "SQL query sem parametrização",
        "description": "Concatenação de strings em queries SQL abre vulnerabilidade de SQL Injection.",
        "pattern": r'execute\s*\(\s*["\'].*\%s.*["\']',
        "languages": ["python"],
    },
    {
        "rule": "missing-input-validation",
        "severity": "medium",
        "title": "Sem validação de input",
        "description": "Dados do usuário usados sem validação. Pode causar erros inesperados ou vulnerabilidades.",
        "pattern": r'request\.(args|form|json|data)\[',
        "languages": ["python"],
    },
    {
        "rule": "missing-type-hints",
        "severity": "low",
        "title": "Função sem tipagem",
        "description": "Funções sem type hints dificultam manutenção e detecção de bugs em tempo de desenvolvimento.",
        "pattern": r'^def \w+\([^)]*\)\s*:',
        "languages": ["python"],
    },
    {
        "rule": "long-function",
        "severity": "low",
        "title": "Função muito longa",
        "description": "Funções com mais de 50 linhas são difíceis de testar e manter. Considere refatorar.",
        "pattern": None,
        "languages": ["python", "javascript", "typescript"],
    },
    {
        "rule": "console-log-left",
        "severity": "low",
        "title": "console.log() em código de produção",
        "description": "Logs de debug esquecidos no código. Use um logger adequado.",
        "pattern": r'console\.log\(',
        "languages": ["javascript", "typescript"],
    },
    {
        "rule": "any-type",
        "severity": "medium",
        "title": "Tipo `any` explícito",
        "description": "Uso de `any` desativa a verificação de tipos do TypeScript. Use tipos específicos.",
        "pattern": r':\s*any[\s,;)]',
        "languages": ["typescript"],
    },
]

FIXES = {
    "undefined-variable": {
        "diff": '- cep_response = requests.get(f"https://viacep.com.br/ws/{cep}/json/")\n- dados = cep_response.json()\n+ def consultar_cep(cep: str) -> dict | None:\n+     if not isinstance(cep, str) or not cep.isdigit() or len(cep) != 8:\n+         return None\n+     r = requests.get(f"https://viacep.com.br/ws/{cep}/json/")\n+     r.raise_for_status()\n+     dados = r.json()\n+     return None if dados.get("erro") else dados',
        "explanation": "Encapsulado em função com tipagem explícita, validação de formato (8 dígitos) e tratamento de HTTP errors."
    },
    "unhandled-http-error": {
        "diff": '- response = requests.get(url)\n- data = response.json()\n+ response = requests.get(url)\n+ response.raise_for_status()  # Levanta HTTPError para 4xx/5xx\n+ data = response.json()',
        "explanation": "Adicionado raise_for_status() para propagar erros HTTP explicitamente em vez de falhar silenciosamente."
    },
    "sql-no-params": {
        "diff": '- cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n+ cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "explanation": "Substituída interpolação de string por parâmetros SQL. Elimina risco de SQL Injection."
    },
    "missing-input-validation": {
        "diff": '- email = request.args["email"]\n+ email = request.args.get("email", "").strip()\n+ if not email or "@" not in email:\n+     return jsonify({"error": "Email inválido"}), 400',
        "explanation": "Adicionada validação com .get() para evitar KeyError e verificação básica de formato."
    },
    "missing-type-hints": {
        "diff": '- def process_user(user, config):\n+ def process_user(user: dict, config: dict) -> dict | None:',
        "explanation": "Type hints adicionadas para facilitar detecção de bugs e melhorar a documentação inline."
    },
    "console-log-left": {
        "diff": '- console.log("debug:", data)\n+ // Removido console.log de produção\n+ logger.debug("debug:", data)  // Use um logger adequado',
        "explanation": "console.log() removido. Recomendado usar um logger configurável (winston, pino) que pode ser desabilitado em produção."
    },
}

def simulate_scan(repo_name: str, language: str = "python"):
    """Simula análise estática e retorna issues encontradas."""
    lang = language.lower()
    issues = []
    applicable = [r for r in RULES if lang in r["languages"] or not r["languages"]]

    # Simula encontrar issues baseado no nome/tipo do repo
    import random
    random.seed(hash(repo_name) % 1000)

    for rule in applicable:
        if random.random() < 0.6:
            files = {
                "python": ["api/client.py", "services/user.py", "routes/main.py", "db/queries.py", "utils/helpers.py"],
                "javascript": ["src/api.js", "components/Form.js", "utils/fetch.js"],
                "typescript": ["src/api.ts", "components/Form.tsx", "types/index.ts"],
            }
            file_list = files.get(lang, ["main.py"])
            issues.append({
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["description"],
                "file_path": random.choice(file_list),
                "line_number": random.randint(5, 120),
                "rule": rule["rule"],
                "fix_diff": FIXES.get(rule["rule"], {}).get("diff", ""),
                "fix_explanation": FIXES.get(rule["rule"], {}).get("explanation", ""),
            })

    high = sum(1 for i in issues if i["severity"] == "high")
    med  = sum(1 for i in issues if i["severity"] == "medium")
    low  = sum(1 for i in issues if i["severity"] == "low")
    # Score: 100 - (high*15 + med*7 + low*3), mínimo 0
    score = max(0, 100 - high * 15 - med * 7 - low * 3)
    return issues, high, med, low, score

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return ok({"name": "CodeFlow API", "version": "1.0.0", "status": "running"})

@app.get("/health")
def health():
    return ok({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

# AUTH
@app.post("/auth/register")
def register():
    body = request.get_json() or {}
    email = (body.get("email") or "").strip().lower()
    name  = (body.get("name")  or "").strip()
    pw    = body.get("password") or ""

    if not email or "@" not in email:
        return error("Email inválido")
    if not name:
        return error("Nome obrigatório")
    if len(pw) < 6:
        return error("Senha deve ter pelo menos 6 caracteres")

    db = get_db()
    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        return error("Email já cadastrado")

    db.execute("INSERT INTO users (email, name, password) VALUES (?,?,?)",
               (email, name, hash_password(pw)))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    token = make_token(user["id"])
    return ok({"token": token, "user": {**row_to_dict(user), "password": None}}, 201)

@app.post("/auth/login")
def login():
    body = request.get_json() or {}
    email = (body.get("email") or "").strip().lower()
    pw    = body.get("password") or ""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=? AND password=?",
                      (email, hash_password(pw))).fetchone()
    if not user:
        return error("Email ou senha inválidos", 401)
    token = make_token(user["id"])
    return ok({"token": token, "user": {**row_to_dict(user), "password": None}})

@app.get("/auth/me")
@require_auth
def me():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (g.user_id,)).fetchone()
    if not user: return error("Usuário não encontrado", 404)
    return ok({**row_to_dict(user), "password": None})

# REPOS
@app.get("/repos")
@require_auth
def list_repos():
    db = get_db()
    repos = db.execute(
        "SELECT r.*, COUNT(DISTINCT s.id) as scan_count FROM repos r "
        "LEFT JOIN scans s ON s.repo_id=r.id "
        "WHERE r.user_id=? AND r.connected=1 GROUP BY r.id ORDER BY r.created_at DESC",
        (g.user_id,)
    ).fetchall()
    return ok(rows_to_list(repos))

@app.post("/repos")
@require_auth
def add_repo():
    body = request.get_json() or {}
    name = (body.get("name") or "").strip()
    full_name = (body.get("full_name") or name).strip()
    language  = (body.get("language") or "python").strip().lower()
    framework = body.get("framework") or ""

    if not name:
        return error("Nome do repositório obrigatório")

    db = get_db()
    user = db.execute("SELECT plan FROM users WHERE id=?", (g.user_id,)).fetchone()
    if user["plan"] == "starter":
        count = db.execute("SELECT COUNT(*) FROM repos WHERE user_id=? AND connected=1", (g.user_id,)).fetchone()[0]
        if count >= 1:
            return error("Plano Starter permite apenas 1 repositório. Faça upgrade para Team.", 403)

    db.execute("INSERT INTO repos (user_id, name, full_name, language, framework) VALUES (?,?,?,?,?)",
               (g.user_id, name, full_name, language, framework))
    db.commit()
    repo = db.execute("SELECT * FROM repos WHERE rowid=last_insert_rowid()").fetchone()
    return ok(row_to_dict(repo), 201)

@app.delete("/repos/<int:repo_id>")
@require_auth
def remove_repo(repo_id):
    db = get_db()
    repo = db.execute("SELECT * FROM repos WHERE id=? AND user_id=?", (repo_id, g.user_id)).fetchone()
    if not repo: return error("Repositório não encontrado", 404)
    db.execute("UPDATE repos SET connected=0 WHERE id=?", (repo_id,))
    db.commit()
    return ok({"message": "Repositório desconectado"})

# SCANS
@app.post("/repos/<int:repo_id>/scan")
@require_auth
def trigger_scan(repo_id):
    db = get_db()
    repo = db.execute("SELECT * FROM repos WHERE id=? AND user_id=?", (repo_id, g.user_id)).fetchone()
    if not repo: return error("Repositório não encontrado", 404)

    # Cria o scan
    db.execute("INSERT INTO scans (repo_id, status) VALUES (?, 'running')", (repo_id,))
    db.commit()
    scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Simula análise
    issues, high, med, low, score = simulate_scan(repo["name"], repo["language"])

    for issue in issues:
        db.execute("""INSERT INTO issues
            (scan_id, repo_id, severity, title, description, file_path, line_number, rule, fix_diff, fix_explanation)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, repo_id, issue["severity"], issue["title"], issue["description"],
             issue["file_path"], issue["line_number"], issue["rule"],
             issue["fix_diff"], issue["fix_explanation"]))

    db.execute("""UPDATE scans SET status='completed', total_issues=?, high_issues=?, med_issues=?, low_issues=?, score=?, finished_at=datetime('now')
               WHERE id=?""", (len(issues), high, med, low, score, scan_id))
    db.commit()

    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return ok({"scan": row_to_dict(scan), "issues_count": len(issues)}, 201)

@app.get("/repos/<int:repo_id>/scans")
@require_auth
def get_scans(repo_id):
    db = get_db()
    repo = db.execute("SELECT * FROM repos WHERE id=? AND user_id=?", (repo_id, g.user_id)).fetchone()
    if not repo: return error("Repositório não encontrado", 404)
    scans = db.execute("SELECT * FROM scans WHERE repo_id=? ORDER BY started_at DESC LIMIT 20", (repo_id,)).fetchall()
    return ok(rows_to_list(scans))

# ISSUES
@app.get("/repos/<int:repo_id>/issues")
@require_auth
def get_issues(repo_id):
    db = get_db()
    repo = db.execute("SELECT * FROM repos WHERE id=? AND user_id=?", (repo_id, g.user_id)).fetchone()
    if not repo: return error("Repositório não encontrado", 404)

    severity = request.args.get("severity")
    status   = request.args.get("status", "open")
    limit    = min(int(request.args.get("limit", 50)), 100)

    query = "SELECT * FROM issues WHERE repo_id=? AND status=?"
    params = [repo_id, status]
    if severity:
        query += " AND severity=?"
        params.append(severity)
    query += " ORDER BY CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC LIMIT ?"
    params.append(limit)

    issues = db.execute(query, params).fetchall()
    return ok(rows_to_list(issues))

@app.get("/issues/<int:issue_id>")
@require_auth
def get_issue(issue_id):
    db = get_db()
    issue = db.execute("""SELECT i.*, r.user_id FROM issues i
                          JOIN repos r ON r.id=i.repo_id
                          WHERE i.id=? AND r.user_id=?""", (issue_id, g.user_id)).fetchone()
    if not issue: return error("Issue não encontrado", 404)
    return ok(row_to_dict(issue))

@app.patch("/issues/<int:issue_id>/status")
@require_auth
def update_issue_status(issue_id):
    body = request.get_json() or {}
    new_status = body.get("status")
    if new_status not in ("open", "fixed", "ignored"):
        return error("Status inválido. Use: open, fixed, ignored")
    db = get_db()
    issue = db.execute("""SELECT i.id FROM issues i JOIN repos r ON r.id=i.repo_id
                          WHERE i.id=? AND r.user_id=?""", (issue_id, g.user_id)).fetchone()
    if not issue: return error("Issue não encontrado", 404)
    db.execute("UPDATE issues SET status=? WHERE id=?", (new_status, issue_id))
    db.commit()
    return ok({"message": f"Issue marcado como {new_status}"})

# PULL REQUESTS
@app.post("/issues/<int:issue_id>/fix")
@require_auth
def create_fix_pr(issue_id):
    db = get_db()
    issue = db.execute("""SELECT i.*, r.name as repo_name FROM issues i
                          JOIN repos r ON r.id=i.repo_id
                          WHERE i.id=? AND r.user_id=?""", (issue_id, g.user_id)).fetchone()
    if not issue: return error("Issue não encontrado", 404)
    if not issue["fix_diff"]:
        return error("Nenhum fix disponível para este issue")

    pr_num = db.execute("SELECT COALESCE(MAX(pr_number),0)+1 FROM pull_requests WHERE repo_id=?",
                        (issue["repo_id"],)).fetchone()[0]

    db.execute("""INSERT INTO pull_requests (repo_id, issue_id, pr_number, title, url, status)
                  VALUES (?,?,?,?,?,?)""",
               (issue["repo_id"], issue_id, pr_num,
                f"fix: {issue['title']}",
                f"https://github.com/startup/{issue['repo_name']}/pull/{pr_num}",
                "open"))
    db.execute("UPDATE issues SET status='fixed' WHERE id=?", (issue_id,))
    db.commit()

    pr = db.execute("SELECT * FROM pull_requests WHERE rowid=last_insert_rowid()").fetchone()
    return ok(row_to_dict(pr), 201)

@app.get("/repos/<int:repo_id>/pull-requests")
@require_auth
def get_prs(repo_id):
    db = get_db()
    repo = db.execute("SELECT * FROM repos WHERE id=? AND user_id=?", (repo_id, g.user_id)).fetchone()
    if not repo: return error("Repositório não encontrado", 404)
    prs = db.execute("SELECT * FROM pull_requests WHERE repo_id=? ORDER BY created_at DESC", (repo_id,)).fetchall()
    return ok(rows_to_list(prs))

# DASHBOARD
@app.get("/dashboard")
@require_auth
def dashboard():
    db = get_db()
    repos = db.execute("SELECT id FROM repos WHERE user_id=? AND connected=1", (g.user_id,)).fetchall()
    repo_ids = [r["id"] for r in repos]
    if not repo_ids:
        return ok({"metrics": {}, "top_issues": [], "activity": [], "repos": []})

    placeholders = ",".join("?" * len(repo_ids))

    metrics = db.execute(f"""
        SELECT
            COUNT(*) FILTER(WHERE status='open') as open_issues,
            COUNT(*) FILTER(WHERE status='fixed') as fixed_issues
        FROM issues WHERE repo_id IN ({placeholders})
    """, repo_ids).fetchone()

    pr_count = db.execute(f"""SELECT COUNT(*) FROM pull_requests
        WHERE repo_id IN ({placeholders}) AND status='open'""", repo_ids).fetchone()[0]

    last_scan = db.execute(f"""SELECT score FROM scans
        WHERE repo_id IN ({placeholders}) ORDER BY started_at DESC LIMIT 1""", repo_ids).fetchone()
    score = last_scan["score"] if last_scan else 0

    top_rules = db.execute(f"""
        SELECT rule, title, COUNT(*) as count FROM issues
        WHERE repo_id IN ({placeholders}) AND status='open'
        GROUP BY rule ORDER BY count DESC LIMIT 6
    """, repo_ids).fetchall()

    recent_issues = db.execute(f"""
        SELECT i.*, r.name as repo_name FROM issues i
        JOIN repos r ON r.id=i.repo_id
        WHERE i.repo_id IN ({placeholders})
        ORDER BY i.created_at DESC LIMIT 10
    """, repo_ids).fetchall()

    repos_detail = db.execute(f"""
        SELECT r.*, s.score, s.total_issues, s.finished_at as last_scan
        FROM repos r LEFT JOIN scans s ON s.id=(
            SELECT id FROM scans WHERE repo_id=r.id ORDER BY started_at DESC LIMIT 1)
        WHERE r.id IN ({placeholders})
    """, repo_ids).fetchall()

    return ok({
        "metrics": {
            "open_issues": metrics["open_issues"],
            "fixed_issues": metrics["fixed_issues"],
            "open_prs": pr_count,
            "code_score": score,
        },
        "top_rules": rows_to_list(top_rules),
        "recent_issues": rows_to_list(recent_issues),
        "repos": rows_to_list(repos_detail),
    })

# TEAM
@app.get("/team")
@require_auth
def list_team():
    db = get_db()
    members = db.execute("SELECT * FROM team_members WHERE user_id=? ORDER BY added_at DESC", (g.user_id,)).fetchall()
    return ok(rows_to_list(members))

@app.post("/team")
@require_auth
def add_member():
    body = request.get_json() or {}
    name  = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip().lower()
    role  = body.get("role", "developer")
    if not name or not email:
        return error("Nome e email obrigatórios")

    db = get_db()
    user = db.execute("SELECT plan FROM users WHERE id=?", (g.user_id,)).fetchone()
    if user["plan"] == "starter":
        return error("Gerenciamento de time disponível nos planos Team e Scale.", 403)

    db.execute("INSERT INTO team_members (user_id, name, email, role) VALUES (?,?,?,?)",
               (g.user_id, name, email, role))
    db.commit()
    member = db.execute("SELECT * FROM team_members WHERE rowid=last_insert_rowid()").fetchone()
    return ok(row_to_dict(member), 201)

# PLAN UPGRADE
@app.post("/billing/upgrade")
@require_auth
def upgrade_plan():
    body = request.get_json() or {}
    plan = body.get("plan")
    if plan not in ("starter", "team", "scale"):
        return error("Plano inválido. Opções: starter, team, scale")
    db = get_db()
    db.execute("UPDATE users SET plan=? WHERE id=?", (plan, g.user_id))
    db.commit()
    return ok({"message": f"Plano atualizado para {plan}", "plan": plan})

# ─── STARTUP ──────────────────────────────────────────────────────────────────

with app.app_context():
    init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"\n  🌊 CodeFlow API rodando em http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=True)
