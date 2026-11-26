# РГР: аудит захищеності OWASP WebGoat (варіант 9 — автентифікація та сесії)

Цей репозиторій містить середовище, виправлення, регресійні тести та результати аналізу до звіту
`report/RGR_WebGoat_variant9.docx`.

**Коміт, що відповідає зданій роботі (код, тести, виправлення): `88fba89`.**

| Шлях | Вміст |
|---|---|
| `webgoat/` | OWASP WebGoat v2025.3 (базовий коміт `1f11f8a` — код без змін) з виправленнями V1–V7 |
| `webgoat/src/test/java/org/owasp/webgoat/rgr/` | регресійні тести `V1…V7*RegressionTest` і `RgrEvidenceTest`, який записує докази |
| `docker-compose.yml`, `deploy/` | ізольоване середовище: мережа `internal: true`, вхід лише через `127.0.0.1` |
| `tools/semgrep/rgr-auth-session.yml` | власні правила Semgrep для профілю аудиту |
| `tools/osv_sca.py`, `tools/compare_scans.py` | SCA (SBOM CycloneDX → OSV.dev) і порівняння «до/після» |
| `scans/before`, `scans/after` | повні звіти інструментів і surefire |
| `scans/evidence/{before,after}` | транскрипти «запит → відповідь» для V1–V7 |
| `report/` | звіт (DOCX) і діаграма потоків даних |

## Історія комітів

1. `Baseline` — WebGoat v2025.3 без змін.
2. `test(rgr)` — регресійні тести; на базовому коді вони **падають**, що й доводить наявність вразливостей.
3. `fix(rgr)` — виправлення V1–V7 і оновлення залежностей; після нього тести **проходять**.
4. Подальші коміти — інструменти, результати сканування, звіт.

## Відтворення

Потрібні JDK 23 і Maven 3.9.

```bash
cd webgoat
mvn -B -DskipTests package                       # збирання
mvn -B test -Dtest='org.owasp.webgoat.rgr.V*Test' # регресійні тести V1–V7
mvn -B test                                       # усі модульні тести (266)
java -jar target/webgoat-2025.3.jar               # локальний запуск, слухає лише 127.0.0.1:8080
```

Ізольований запуск у контейнері (потрібен Docker):

```bash
(cd webgoat && mvn -B -DskipTests package)
docker compose up --build -d   # http://127.0.0.1:8080/WebGoat
```

Сканування описано в додатку А звіту. FindSecBugs можна завантажити командою
`mvn dependency:copy -Dartifact=com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0 -DoutputDirectory=tools/fsb`.

> Усі перевірки виконувалися лише над власним локальним екземпляром застосунку.
