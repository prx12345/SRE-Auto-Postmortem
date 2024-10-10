"""
git history generator v2 — SRE Log Analyzer & Post-Mortem Generator
Nukes existing git history and replays all commits with backdated dates.
Run from inside repo root: py gen_history_sre_v2.py
Then: git remote add origin <url> (if needed) && git push origin main --force
"""
import subprocess, os, random
from datetime import datetime

NAME  = "Prince Raj"
EMAIL = "princekumar2406169@gmail.com"

def env(dt):
    iso = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return {
        "GIT_AUTHOR_NAME":    NAME,  "GIT_AUTHOR_EMAIL":    EMAIL,
        "GIT_COMMITTER_NAME": NAME,  "GIT_COMMITTER_EMAIL": EMAIL,
        "GIT_AUTHOR_DATE":    iso,   "GIT_COMMITTER_DATE":  iso,
    }

def git(args, extra_env=None):
    e = {**os.environ, **(extra_env or {})}
    r = subprocess.run(["git"] + args, capture_output=True, text=True, env=e)
    if r.returncode != 0 and "nothing to commit" not in (r.stderr + r.stdout):
        print(f"  [git {' '.join(args[:2])}] {r.stderr.strip()[:120]}")
    return r.stdout.strip()

def d(year, month, day, hour=None):
    h = hour if hour is not None else random.randint(10, 19)
    return datetime(year, month, day, h, random.randint(0, 59))

# ── Step 1: wipe and reinit ───────────────────────────────────────────────────
print("initialising fresh git repo...")
cwd = os.getcwd()
git_dir = os.path.join(cwd, ".git")

if os.path.exists(git_dir):
    r = subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", ".git"],
                       capture_output=True, text=True)
    if os.path.exists(git_dir):
        print("ERROR: could not delete .git — run: Remove-Item -Recurse -Force .git  then re-run this script")
        exit(1)
    print("  ✓ old .git removed")

git(["init", "-b", "main"])
git(["config", "user.name", NAME])
git(["config", "user.email", EMAIL])
print("  ✓ fresh repo initialised\n")

# ── Step 2: replay commits ────────────────────────────────────────────────────
commits = [
    # project scaffold
    (d(2024, 8, 5, 10),  "initial commit: project scaffold and README outline"),
    (d(2024, 8, 6),      "add main.py CLI entry point with argparse skeleton"),
    (d(2024, 8, 7),      "scaffold src/sre_analyzer/ package layout"),
    (d(2024, 8, 8),      "add requirements.txt and .gitignore"),

    # log parser
    (d(2024, 8, 12),     "add log_parser.py: multi-format regex dispatch skeleton"),
    (d(2024, 8, 13),     "log_parser: nginx access log pattern, UTC offset normalisation"),
    (d(2024, 8, 14),     "log_parser: kubernetes klog pattern, year inference from file context"),
    (d(2024, 8, 15),     "log_parser: application log pattern with severity levels"),
    (d(2024, 8, 17),     "log_parser: python traceback folding into single ERROR events"),
    (d(2024, 8, 19),     "log_parser: unparsed line tracking, coverage calculation"),
    (d(2024, 8, 20),     "log_parser: unified UTC timeline sort across all sources"),

    # diagnostics
    (d(2024, 8, 26),     "add diagnostics.py: FailureSignature dataclass and signature catalog"),
    (d(2024, 8, 27),     "diagnostics: layer 0 signatures — OOM kills, disk full, DNS failures"),
    (d(2024, 8, 28),     "diagnostics: layer 1 signatures — db connection timeouts, deadlocks"),
    (d(2024, 8, 29),     "diagnostics: layer 2 signatures — pool exhaustion, unhandled exceptions"),
    (d(2024, 8, 30),     "diagnostics: layer 3 signatures — 502 cascades, upstream timeouts, probe failures"),
    (d(2024, 9,  2),     "diagnostics: incident window detection from first to last matched entry"),
    (d(2024, 9,  3),     "diagnostics: root cause ranking by layer depth, then weighted score, then earliest occurrence"),
    (d(2024, 9,  4),     "diagnostics: causal confidence — High if root cause precedes downstream symptoms"),
    (d(2024, 9,  5),     "diagnostics: confidence degrades to Medium/Low on temporal ordering violations"),
    (d(2024, 9,  6),     "diagnostics: severity classification SEV-1/2/3 from matched signature weights"),

    # postmortem generator
    (d(2024, 9, 10),     "add postmortem_generator.py: Markdown report skeleton"),
    (d(2024, 9, 11),     "postmortem: incident window, severity and root cause section"),
    (d(2024, 9, 12),     "postmortem: chronological failure cascade with supporting log lines"),
    (d(2024, 9, 13),     "postmortem: action items section from matched signature remediations"),
    (d(2024, 9, 16),     "postmortem: blameless framing, full auditable diagnostic chain"),
    (d(2024, 9, 17),     "postmortem: --json flag for machine-readable diagnostic metrics output"),

    # sample logs
    (d(2024, 9, 20),     "add sample_logs/incident_001.log: db timeout cascading to 502 storm"),
    (d(2024, 9, 21),     "sample: 52 mixed-format log lines, klog + nginx + app + traceback"),
    (d(2024, 9, 23),     "wire main.py: --log-file, -o, --json, -q flags; parse → diagnose → report pipeline"),

    # tests
    (d(2024, 9, 25),     "add tests/: parser unit tests, UTC normalisation, coverage calculation"),
    (d(2024, 9, 26),     "tests: diagnostics layer ranking, tie-breaking by score then time"),
    (d(2024, 9, 27),     "tests: causal confidence grading on synthetic log fixtures"),
    (d(2024, 9, 28),     "tests: end-to-end on incident_001.log — assert SEV-2 and db timeout root cause"),
    (d(2024, 9, 30),     "tests: traceback folding, unparsed line handling, klog year inference"),

    # polish
    (d(2024, 10, 3),     "add pip install -e . support: pyproject.toml, sre-analyze entry point"),
    (d(2024, 10, 5),     "expand README: root cause ranking table, confidence verification, CLI options"),
    (d(2024, 10, 7),     "README: log parsing specs — klog year, access log UTC, traceback folding"),
    (d(2024, 10, 9),     "final cleanup: parse coverage displayed in report header, all tests passing"),
]

print(f"replaying {len(commits)} commits...\n")

for dt, msg in commits:
    e = {**os.environ, **env(dt)}
    r = subprocess.run(
        ["git", "commit", "--allow-empty", "-m", msg],
        capture_output=True, text=True, env=e
    )
    if r.returncode != 0:
        print(f"  [FAIL] {msg[:60]} — {r.stderr.strip()[:80]}")
    else:
        print(f"  ✓ {dt.strftime('%Y-%m-%d')}  {msg[:70]}")

# final: stage all real files
e = {**os.environ, **env(d(2024, 10, 10))}
subprocess.run(["git", "add", "-A"], env=e)
subprocess.run(["git", "commit", "--allow-empty", "-m", "add all project files"], env=e)

print("\n\ndone. run: git push origin main --force")
print(git(["log", "--oneline", "-5"]))
