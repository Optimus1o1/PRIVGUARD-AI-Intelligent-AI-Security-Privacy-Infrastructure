# Contributing to PRIVGUARD AI

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI**  

---

## 1. Development Standards & Guidelines

We welcome contributions that strengthen PRIVGUARD AI. As an enterprise security enforcement layer, every contribution must satisfy strict quality, security, and supply-chain criteria.

### Core Tenets
1. **Conventional Commits**: All commit messages must follow the Conventional Commits specification:
   `feat(scope): description`, `fix(scope): description`, `test(scope): description`, `docs(scope): description`.
2. **Preserve Security Invariants**: Never weaken an authorization check, bypass access control, or disable fail-closed error handling to make a test pass.
3. **Zero Secrets in Code or History**: Never commit real API keys, tokens, or credentials. Always use `scripts/init_secrets.py` or `.env.example`.
4. **Reproducible Dependencies**:
   - Python dependencies must be audited via `pip-audit`.
   - Node.js dependencies must be audited via `npm audit` and have a committed `package-lock.json`.

---

## 2. Local Quality & Security Gates

Before submitting a Pull Request, run the complete local gate suite:

### 2.1 Backend Quality Gates
```bash
# 1. Linting & Formatting verification
.\.venv\Scripts\ruff.exe check backend/app
.\.venv\Scripts\ruff.exe format --check backend/app

# 2. Static AST Security Analysis
.\.venv\Scripts\bandit.exe -r backend/app -ll -ii

# 3. Dependency Security Audit
.\.venv\Scripts\pip-audit.exe -r backend/requirements.txt

# 4. Full Automated Test Suite (All tests must pass)
.\.venv\Scripts\python.exe -m pytest backend/tests/ -q
```

### 2.2 Frontend Quality Gates
```bash
# 1. Dependency Security Audit
npm audit --prefix frontend

# 2. TypeScript Static Typecheck
npx tsc --noEmit --project frontend/tsconfig.json

# 3. Next.js Production Build
npm run build --prefix frontend
```

### 2.3 Secret Scanning
```bash
# Run Gitleaks across repository
gitleaks detect --source . --config .gitleaks.toml
```

---

## 3. Pull Request Requirements

When opening a Pull Request:
- Target the `master` branch.
- Ensure all GitHub Actions CI checks pass (`backend`, `frontend`, `infrastructure`).
- Include automated tests in `backend/tests/` for any new logic or bugfix.
- For architectural changes touching more than 2 files, discuss the implementation design upfront.

