"""Dockerfile intelligence: parse, 'captain' best-practice lint, safe auto-fixes, plain-language explainer.

Pure text in, text out. No Docker daemon needed, so the lint, the fixes and the explainer work even when the
real tools (hadolint, trivy, docker) are not installed. Every fix is deterministic and idempotent.
"""
from __future__ import annotations

import json
import re
import shlex

PIN = {"python": "3.12-slim", "node": "22-slim", "alpine": "3.20", "debian": "12-slim", "ubuntu": "24.04",
       "golang": "1.23", "nginx": "1.27-alpine", "redis": "7-alpine", "postgres": "16-alpine"}
SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)", re.I)
IGNORE = """# Keep the build context small and free of secrets (faster builds, nothing sensitive in the image).
.git
.gitignore
.dockerignore
Dockerfile*
docker-compose*.yml
**/__pycache__
**/*.pyc
.venv
venv
node_modules
.env
.env.*
*.pem
*.key
.terraform
*.tfstate*
.idea
.vscode
*.md
"""


# ------------------------------------------------------------------ parsing
def parse(text: str) -> list[dict]:
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        if not lines[i].strip() or lines[i].strip().startswith("#"):
            i += 1
            continue
        start, parts = i, []
        while True:
            seg = lines[i].rstrip()
            if parts and seg.strip().startswith("#"):
                i += 1
                if i >= len(lines):
                    break
                continue
            cont = seg.endswith("\\")
            parts.append(seg[:-1].strip() if cont else seg.strip())
            if not cont or i + 1 >= len(lines):
                break
            i += 1
        end = min(i, len(lines) - 1)
        i += 1
        full = " ".join(p for p in parts if p)
        kw, _, args = full.partition(" ")
        out.append({"kw": kw.upper(), "args": args.strip(), "start": start, "end": end})
    return out


def stages(ins: list[dict]) -> list[dict]:
    st = []
    for n, x in enumerate(ins):
        if x["kw"] == "FROM":
            toks = [t for t in x["args"].split() if not t.startswith("--")]
            alias = toks[2] if len(toks) >= 3 and toks[1].upper() == "AS" else None
            st.append({"base": toks[0] if toks else "", "alias": alias, "first": n, "ins": []})
        elif st:
            st[-1]["ins"].append(x)
    return st


def _repo_tag(image: str) -> tuple[str, str | None]:
    if "@sha256:" in image:
        return image.split("@")[0], "digest"
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = image.rsplit(":", 1)
        return repo, tag
    return image, None


def _repo_name(image: str) -> str:
    return _repo_tag(image)[0].rsplit("/", 1)[-1]


def _is_stage_ref(image: str, sts: list[dict]) -> bool:
    return image in {s["alias"] for s in sts if s["alias"]}


# ------------------------------------------------------------------ lint
RULES = {
    "CAP001": ("high", "Base image is not pinned to a version (latest / no tag): builds change without notice"),
    "CAP002": ("high", "Container runs as root: a bug in the app becomes a root-level problem"),
    "CAP003": ("medium", "No HEALTHCHECK: Docker cannot tell a hung app from a healthy one"),
    "CAP004": ("medium", "No .dockerignore: .git, secrets and junk can leak into the build context and image"),
    "CAP005": ("medium", "apt-get install without --no-install-recommends and/or without cleaning the package lists"),
    "CAP006": ("low", "pip install without --no-cache-dir: the download cache is baked into a layer"),
    "CAP007": ("low", "Shell-form CMD/ENTRYPOINT: the app is not PID 1 and will not receive stop signals cleanly"),
    "CAP008": ("medium", "Single-stage build: build tools and caches ship inside the final image"),
    "CAP009": ("medium", "Source is copied before dependencies are installed: every code edit re-installs everything"),
    "CAP010": ("high", "Secret-looking ENV/ARG value or remote ADD baked into the image"),
    "CAP011": ("low", "ADD used where COPY is enough (ADD has hidden behaviour)"),
}


def _f(line: int, rule: str, extra: str = "") -> dict:
    sev, msg = RULES[rule]
    return {"file": "Dockerfile", "line": line + 1, "severity": sev, "rule": rule, "msg": msg + (f" ({extra})" if extra else "")}


def _wide_copy(x: dict) -> bool:
    if x["kw"] != "COPY":
        return False
    t = [a for a in x["args"].split() if not a.startswith("--")]
    return len(t) >= 2 and t[0] in (".", "./", "*")


def _dep_install(x: dict) -> bool:
    return x["kw"] == "RUN" and bool(re.search(r"pip3?\s+install\s.*-r\s|npm\s+(ci|install)\b", x["args"]))


def lint(text: str, has_dockerignore: bool) -> list[dict]:
    ins = parse(text)
    sts = stages(ins)
    fs: list[dict] = []
    if not has_dockerignore:
        fs.append(_f(0, "CAP004"))
    if not sts:
        return fs
    for s in sts:
        img = s["base"]
        if not img or img == "scratch" or "$" in img or _is_stage_ref(img, sts):
            continue
        _, tag = _repo_tag(img)
        if tag in (None, "latest"):
            fs.append(_f(ins[s["first"]]["start"], "CAP001", img))
    fin = sts[-1]
    users = [x for x in fin["ins"] if x["kw"] == "USER"]
    last_line = max((x["start"] for x in fin["ins"] if x["kw"] in ("CMD", "ENTRYPOINT")), default=ins[fin["first"]]["start"])
    if not users or users[-1]["args"].split(":")[0].strip() in ("root", "0"):
        fs.append(_f(last_line, "CAP002"))
    hc = [x for x in fin["ins"] if x["kw"] == "HEALTHCHECK"]
    if not hc or hc[-1]["args"].upper().startswith("NONE"):
        fs.append(_f(last_line, "CAP003"))
    for s in sts:
        env_nocache = any(x["kw"] == "ENV" and "PIP_NO_CACHE_DIR" in x["args"] for x in s["ins"])
        wide = None
        for x in s["ins"]:
            a = x["args"]
            if x["kw"] == "RUN":
                if re.search(r"\bapt(-get)?\s+(-\S+\s+)*install\b", a):
                    miss = []
                    if "--no-install-recommends" not in a:
                        miss.append("--no-install-recommends")
                    if "/var/lib/apt/lists" not in a:
                        miss.append("clean /var/lib/apt/lists")
                    if miss:
                        fs.append(_f(x["start"], "CAP005", ", ".join(miss)))
                if re.search(r"\bpip3?\s+install\b", a) and "--no-cache-dir" not in a and not env_nocache:
                    fs.append(_f(x["start"], "CAP006"))
            if x["kw"] in ("CMD", "ENTRYPOINT") and not a.startswith("["):
                fs.append(_f(x["start"], "CAP007"))
            if x["kw"] in ("ENV", "ARG"):
                for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)=(\S+)", a):
                    if SECRET_NAME.search(m.group(1)) and not m.group(2).startswith("$"):
                        fs.append(_f(x["start"], "CAP010", m.group(1)))
            if x["kw"] == "ADD":
                src = a.split()[0] if a.split() else ""
                if re.match(r"https?://", src):
                    fs.append(_f(x["start"], "CAP010", "remote ADD"))
                elif not re.search(r"\.(tar|tgz|gz|xz|bz2)(\b|$)", src):
                    fs.append(_f(x["start"], "CAP011"))
            if _wide_copy(x) and wide is None:
                wide = x
            if wide is not None and _dep_install(x):
                fs.append(_f(wide["start"], "CAP009"))
                wide = None
    if len(sts) == 1 and any(
            x["kw"] == "RUN" and re.search(r"pip3?\s+install|npm\s+(ci|install)|go\s+build|build-essential|\bgcc\b", x["args"])
            for x in fin["ins"]):
        fs.append(_f(ins[fin["first"]]["start"], "CAP008"))
    return sorted(fs, key=lambda f: (f["line"], f["rule"]))


# ------------------------------------------------------------------ fixes (text -> text)
def _lines(text):
    return text.split("\n")


def _replace(text: str, x: dict, new: list[str]) -> str:
    ls = _lines(text)
    ls[x["start"]: x["end"] + 1] = new
    return "\n".join(ls)


def _run_fmt(cmds: list[str]) -> list[str]:
    cmds = [c.strip() for c in cmds if c.strip()]
    if len(cmds) <= 1:
        return ["RUN " + (cmds[0] if cmds else "true")]
    return ["RUN " + cmds[0] + " \\"] + [f"    && {c}" + (" \\" if i < len(cmds) - 2 else "") for i, c in enumerate(cmds[1:])]


def _each(text: str, kw: str, fn) -> str:
    """Apply fn(instruction)->new lines|None to every instruction of kind kw, bottom-up so line numbers stay valid."""
    for x in reversed([y for y in parse(text) if y["kw"] == kw]):
        new = fn(x)
        if new is not None:
            text = _replace(text, x, new)
    return text


def fix_pin(text: str, ctx: dict) -> str:
    sts = stages(parse(text))

    def f(x):
        toks = x["args"].split()
        idx = next((i for i, t in enumerate(toks) if not t.startswith("--")), None)
        if idx is None:
            return None
        img = toks[idx]
        if img == "scratch" or "$" in img or _is_stage_ref(img, sts):
            return None
        repo, tag = _repo_tag(img)
        if tag not in (None, "latest") or repo.rsplit("/", 1)[-1] not in PIN or "/" in repo and not repo.startswith("library/"):
            return None
        toks[idx] = f"{repo}:{PIN[repo.rsplit('/', 1)[-1]]}"
        return ["FROM " + " ".join(toks)]
    return _each(text, "FROM", f)


def fix_apt(text: str, ctx: dict) -> str:
    def f(x):
        a = x["args"]
        if not re.search(r"\bapt(-get)?\s+(-\S+\s+)*install\b", a):
            return None
        if "--no-install-recommends" not in a:
            a = re.sub(r"(\bapt(?:-get)?\s+(?:-\S+\s+)*install)\b", r"\1 --no-install-recommends", a, count=1)
        cmds = [c for c in re.split(r"\s*&&\s*", a)]
        if "/var/lib/apt/lists" not in a:
            cmds.append("rm -rf /var/lib/apt/lists/*")
        return _run_fmt(cmds)
    return _each(text, "RUN", f)


def fix_pip(text: str, ctx: dict) -> str:
    def f(x):
        a = x["args"]
        if not re.search(r"\bpip3?\s+install\b", a) or "--no-cache-dir" in a:
            return None
        a = re.sub(r"(\bpip3?\s+install)\b", r"\1 --no-cache-dir", a, count=1)
        return _run_fmt(re.split(r"\s*&&\s*", a))
    return _each(text, "RUN", f)


def _final(text: str):
    ins = parse(text)
    sts = stages(ins)
    return ins, sts, (sts[-1] if sts else None)


def _anchor(text: str) -> int:
    """Line index to insert 'final settings' before: the last CMD/ENTRYPOINT of the last stage, else end of file."""
    ins, sts, fin = _final(text)
    if not fin:
        return len(_lines(text))
    ends = [x["start"] for x in fin["ins"] if x["kw"] in ("CMD", "ENTRYPOINT")]
    return max(ends) if ends else len(_lines(text.rstrip("\n"))) + 0


def _insert(text: str, at: int, new: list[str]) -> str:
    ls = _lines(text)
    ls[at:at] = new
    return "\n".join(ls)


APP_ID = 10001  # numeric on purpose: hadolint DL3066, and Kubernetes runAsNonRoot can only verify a number


def _user_cmds(base: str) -> tuple[list[str], str] | None:
    name = _repo_name(base)
    if name == "node":
        return [], "node"
    if "alpine" in base:
        return [f"RUN addgroup -S -g {APP_ID} app && adduser -S -u {APP_ID} -G app -H app"], f"{APP_ID}:{APP_ID}"
    if name in ("python", "debian", "ubuntu") or "slim" in base or "bookworm" in base:
        return [f"RUN groupadd --system --gid {APP_ID} app && useradd --system --uid {APP_ID} --gid app --no-create-home app"], f"{APP_ID}:{APP_ID}"
    return None


def fix_user(text: str, ctx: dict) -> str | None:
    ins, sts, fin = _final(text)
    if not fin:
        return None
    users = [x for x in fin["ins"] if x["kw"] == "USER"]
    if users and users[-1]["args"].split(":")[0].strip() not in ("root", "0"):
        return None
    r = _user_cmds(fin["base"])
    if r is None:
        return None
    run_lines, user = r
    return _insert(text, _anchor(text), run_lines + [f"USER {user}"])


def healthcheck_line(port: int, path: str) -> str:
    code = f"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:{port}{path}', timeout=2).status == 200 else 1)"
    return ("HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \\\n"
            f"    CMD [\"python\", \"-c\", {json.dumps(code)}]")


def fix_health(text: str, ctx: dict) -> str | None:
    ins, sts, fin = _final(text)
    if not fin or _repo_name(fin["base"]) != "python":
        return None
    hc = [x for x in fin["ins"] if x["kw"] == "HEALTHCHECK"]
    if hc and not hc[-1]["args"].upper().startswith("NONE"):
        return None
    port = next((int(m.group(1)) for x in fin["ins"] if x["kw"] == "EXPOSE" for m in [re.search(r"(\d+)", x["args"])] if m), ctx["port"])
    return _insert(text, _anchor(text), healthcheck_line(port, ctx["health_path"]).split("\n"))


def fix_cmd(text: str, ctx: dict) -> str | None:
    def f(x):
        a = x["args"]
        if a.startswith("["):
            return None
        try:
            toks = shlex.split(a)
        except ValueError:
            return None
        if not toks or any(t in ("&&", "||", "|", ";", ">", "<") for t in toks) or "$" in a:
            return None
        return [f"{x['kw']} {json.dumps(toks)}"]
    new = _each(text, "CMD", f)
    return _each(new, "ENTRYPOINT", f)


def fix_cache_order(text: str, ctx: dict) -> str | None:
    ins = parse(text)
    for n, x in enumerate(ins):
        if not _wide_copy(x):
            continue
        for y in ins[n + 1:]:
            if y["kw"] == "FROM":
                break
            if _dep_install(y):
                toks = [t for t in x["args"].split() if not t.startswith("--")]
                dest = toks[-1]
                d = "./" if dest in (".", "./") else dest.rstrip("/") + "/"
                pm = re.search(r"-r\s+(\S+)", y["args"])
                pre = f"COPY {pm.group(1)} {d}" if pm else "COPY package.json package-lock.json* " + d
                ls = _lines(text)
                copy_txt = ls[x["start"]: x["end"] + 1]
                ls[y["end"] + 1:y["end"] + 1] = copy_txt
                ls[y["start"]:y["start"]] = [pre]
                del ls[x["start"]: x["end"] + 1]
                return "\n".join(ls)
            if y["kw"] not in ("WORKDIR", "ENV", "ARG", "USER"):
                break
    return None


def fix_multistage(text: str, ctx: dict) -> str | None:
    ins, sts, fin = _final(text)
    if len(sts) != 1 or _repo_name(fin["base"]) != "python":
        return None
    req = None
    for x in fin["ins"]:
        m = x["kw"] == "RUN" and re.search(r"pip3?\s+install\b.*?-r\s+(\S+)", x["args"])
        if m:
            req = m.group(1)
    if not req:
        return None
    base = fin["base"]
    ur = _user_cmds(base)
    if ur is None or not ur[0]:
        return None
    ex_env = [x["args"] for x in fin["ins"] if x["kw"] == "ENV" and not x["args"].lstrip().startswith("PATH")]
    apt = [x for x in fin["ins"] if x["kw"] == "RUN" and re.search(r"\bapt(-get)?\s+(-\S+\s+)*install\b", x["args"])]
    wd = next((x["args"] for x in reversed(fin["ins"]) if x["kw"] == "WORKDIR"), "/app")
    port = next((m.group(1) for x in fin["ins"] if x["kw"] == "EXPOSE" for m in [re.search(r"(\d+)", x["args"])] if m), str(ctx["port"]))
    cmd = next((x for x in reversed(fin["ins"]) if x["kw"] in ("CMD", "ENTRYPOINT")), None)
    if cmd is None:
        return None
    ca = cmd["args"]
    if not ca.startswith("["):
        try:
            ca = json.dumps(shlex.split(ca))
        except ValueError:
            return None
    out = ["# syntax=docker/dockerfile:1",
           "# Stage 1 - builder: has everything needed to install dependencies. Thrown away after the build.",
           f"FROM {base} AS builder",
           "ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1",
           "RUN python -m venv /opt/venv",
           'ENV PATH="/opt/venv/bin:$PATH"',
           "WORKDIR /build",
           f"COPY {req} ./",
           f"RUN pip install -r {req}",
           "",
           "# Stage 2 - runtime: only what the app needs to run. This is the image you ship.",
           f"FROM {base} AS runtime",
           'ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/opt/venv/bin:$PATH"']
    out += [f"ENV {e}" for e in ex_env]
    for a in apt:
        cmds = re.split(r"\s*&&\s*", a["args"])
        cmds = [re.sub(r"(\bapt(?:-get)?\s+(?:-\S+\s+)*install)\b", r"\1 --no-install-recommends", c, count=1)
                if "install" in c and "--no-install-recommends" not in c else c for c in cmds]
        if "/var/lib/apt/lists" not in a["args"]:
            cmds.append("rm -rf /var/lib/apt/lists/*")
        out += _run_fmt(cmds)
    out += ur[0]
    out += [f"WORKDIR {wd}", "COPY --from=builder /opt/venv /opt/venv", "COPY --chown=app:app . .", f"USER {ur[1]}",
            f"EXPOSE {port}"]
    out += healthcheck_line(int(port), ctx["health_path"]).split("\n")
    out += [f'LABEL org.opencontainers.image.title="{ctx.get("name", "app")}"', f"{cmd['kw']} {ca}"]
    return "\n".join(out) + "\n"


DEBUG_PKGS = {"curl", "wget", "vim", "nano", "less", "procps", "net-tools", "iputils-ping", "telnet", "netcat-openbsd"}
_APT_INSTALL = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\b")
_APT_HOUSEKEEPING = re.compile(r"^(?:apt(?:-get)?\s+(?:-\S+\s+)*(?:update|clean)|rm\s+-rf\s+/var/lib/apt/lists/?\*?)\s*$")


def fix_apt_unused(text: str, ctx: dict) -> str | None:
    """Drop an apt install whose packages are ALL debug tools that nothing else in the final stage mentions.
    All-or-nothing, so 'clears DL3008' is true. A mixed install stays manual: pinning versions breaks when Debian supersedes them."""
    ins, sts, fin = _final(text)
    if not fin:
        return None
    changed = False
    for x in reversed(fin["ins"]):
        if x["kw"] != "RUN" or not _APT_INSTALL.search(x["args"]):
            continue
        cmds = re.split(r"\s*&&\s*", x["args"])
        inst = [c for c in cmds if _APT_INSTALL.search(c)]
        rest = [c for c in cmds if c not in inst]
        if len(inst) != 1 or not all(_APT_HOUSEKEEPING.match(c.strip()) for c in rest):
            continue
        pkgs = [t.split("=")[0] for t in _APT_INSTALL.split(inst[0], 1)[1].split() if not t.startswith("-")]
        others = " ".join(y["args"] for y in fin["ins"] if y is not x)
        if not pkgs or any(p not in DEBUG_PKGS or re.search(rf"(?<![\w.+-]){re.escape(p)}(?![\w.+-])", others) for p in pkgs):
            continue
        text = _replace(text, x, [])
        changed = True
    return text if changed else None


_NAME = re.compile(r"[a-z_][a-z0-9_-]*")


def _opt(t: list[str], names: tuple[str, ...]) -> str | None:
    for i, a in enumerate(t):
        for n in names:
            if a == n and i + 1 < len(t):
                return t[i + 1]
            if n.startswith("--") and a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def _numeric_user(args: str, name: str):
    """Give the group/user this RUN creates fixed numeric ids. (cmds, uid, gid), or None when it is not a pattern we recognise."""
    uid = gid = None
    out, seen_user = [], False
    for c in re.split(r"\s*&&\s*", args):
        t = c.split()
        if t[:1] == ["groupadd"] and t[-1:] == [name]:
            gid = _opt(t, ("--gid", "-g"))
            if gid is None:
                t, gid = [t[0], "--gid", str(APP_ID)] + t[1:], str(APP_ID)
        elif t[:1] == ["addgroup"] and t[-1:] == [name]:
            gid = _opt(t, ("-g",))
            if gid is None:
                t, gid = [t[0], "-g", str(APP_ID)] + t[1:], str(APP_ID)
        elif t[:1] == ["useradd"] and t[-1:] == [name]:
            seen_user, uid = True, _opt(t, ("--uid", "-u"))
            if uid is None:
                t, uid = [t[0], "--uid", str(APP_ID)] + t[1:], str(APP_ID)
        elif t[:1] == ["adduser"] and t[-1:] == [name]:
            seen_user, uid = True, _opt(t, ("-u",))
            if uid is None:
                t, uid = [t[0], "-u", str(APP_ID)] + t[1:], str(APP_ID)
        out.append(" ".join(t))
    if not seen_user or not (uid or "").isdigit() or not (gid or "").isdigit():
        return None
    return out, uid, gid


def fix_user_numeric(text: str, ctx: dict) -> str | None:
    """USER app -> USER <uid>:<gid>, only when this Dockerfile creates that user itself. A base-image user's id is never guessed."""
    ins, sts, fin = _final(text)
    if not fin:
        return None
    users = [x for x in fin["ins"] if x["kw"] == "USER"]
    if not users:
        return None
    u = users[-1]
    name = u["args"].split(":")[0].strip()
    if "$" in u["args"] or name in ("root", "0") or name.isdigit() or not _NAME.fullmatch(name):
        return None
    cre, res = None, None
    for x in fin["ins"]:
        if x["kw"] == "RUN" and x["start"] < u["start"]:
            r = _numeric_user(x["args"], name)
            if r:
                cre, res = x, r
    if cre is None:
        return None
    cmds, uid, gid = res
    text = _replace(text, u, [f"USER {uid}:{gid}"])  # later line first so cre's line numbers stay valid
    return _replace(text, cre, _run_fmt(cmds))


def topology(text: str, app) -> dict:
    """Run-time shape of the container, read from the Dockerfile and the registry. Nothing here is guessed."""
    ins, sts, fin = _final(text)
    fi = fin["ins"] if fin else []
    exposed = sorted({int(n) for x in fi if x["kw"] == "EXPOSE" for n in re.findall(r"\d+", x["args"])})
    vols: list[str] = []
    for x in fi:
        if x["kw"] == "VOLUME":
            a = x["args"].strip()
            try:
                v = json.loads(a) if a.startswith("[") else a.split()
            except ValueError:
                v = a.split()
            vols += [str(i) for i in v]
    users = [x["args"].strip() for x in fi if x["kw"] == "USER"]
    user = users[-1] if users else "root"
    hc = [x for x in fi if x["kw"] == "HEALTHCHECK"]
    cmd = next((x for x in reversed(fi) if x["kw"] in ("ENTRYPOINT", "CMD")), None)
    shell_form = bool(cmd) and not cmd["args"].startswith("[")
    if cmd and not shell_form:
        try:
            cmd_text = " ".join(str(i) for i in json.loads(cmd["args"]))
        except ValueError:
            cmd_text = cmd["args"]
    else:
        cmd_text = cmd["args"] if cmd else ""
    return {"name": app.name, "image": app.image or app.name, "base": fin["base"] if fin else "", "stages": len(sts),
            "user": user, "root": user.split(":")[0].strip() in ("root", "0"),
            "healthcheck": bool(hc) and not hc[-1]["args"].upper().startswith("NONE"), "health_path": app.health_path,
            "ports": [{"host": app.port, "container": app.port, "exposed": app.port in exposed}],
            "extra_ports": [n for n in exposed if n != app.port],
            "volumes": vols, "network": "bridge", "cmd": cmd_text[:80], "shell_form": shell_form}


# id, resolves (our rule + equivalent hadolint / trivy ids), title, plain-language why, fixer
FIXES = [
    ("pin-base", ["CAP001", "DL3006", "DL3007"], "Pin the base image to a version",
     "'latest' means 'whatever was published most recently', so the same Dockerfile builds a different image next month. A version tag makes the build repeatable.", fix_pin),
    ("apt-clean", ["CAP005", "DL3015", "DL3009"], "Slim down apt-get installs",
     "apt installs extra 'recommended' packages and keeps its download lists. Both only make the image bigger and slower to scan.", fix_apt),
    ("pip-nocache", ["CAP006", "DL3042"], "pip: do not keep the download cache",
     "pip stores every downloaded file in a cache. Inside an image that cache is dead weight.", fix_pip),
    ("cmd-exec", ["CAP007", "DL3025"], "Use exec form for CMD",
     "Shell form wraps your app in /bin/sh, so 'docker stop' signals reach the shell instead of the app. Exec form lets the app shut down cleanly.", fix_cmd),
    ("cache-order", ["CAP009"], "Copy dependency list first, source code later",
     "Docker reuses a layer if nothing above it changed. Copying only requirements.txt first means editing code no longer re-installs every library.", fix_cache_order),
    ("non-root", ["CAP002", "DL3002", "AVD-DS-0002", "DS002"], "Run as a non-root user",
     "By default containers run as root. If the app is ever exploited, the attacker starts with the most power possible. A normal user removes that.", fix_user),
    ("healthcheck", ["CAP003", "AVD-DS-0026", "DS026"], "Add a HEALTHCHECK",
     "Lets Docker (and Kubernetes-style tooling) ask the app 'are you alive?' and restart or stop routing to it if not.", fix_health),
    ("apt-unused", ["DL3008"], "Remove debug tools nothing uses",
     "curl, wget and similar tools are installed here but nothing in this Dockerfile calls them (the HEALTHCHECK uses Python). Every extra program is more to patch and more for an attacker to use. If your app code runs curl itself, skip this fix.", fix_apt_unused),
    ("user-numeric", ["DL3066"], "Use a numeric user id",
     "A name like 'app' has to be looked up inside the image. A number (10001) is unambiguous, and Kubernetes can only verify 'runAsNonRoot' when the user is a number.", fix_user_numeric),
]
MULTISTAGE = ("multi-stage", ["CAP008"], "Rewrite as a multi-stage build",
              "Stage 1 installs the libraries with all the build tooling. Stage 2 starts clean and copies in only the finished result, so compilers, caches and pip never ship. Smaller image, smaller attack surface.", fix_multistage)
DOCKERIGNORE = ("dockerignore", ["CAP004"], "Add a .dockerignore",
                "Without it, 'COPY .' sends everything in the folder (.git history, .env files, keys) into the build. This file says what to leave out.", None)


# ------------------------------------------------------------------ explainer (plain language)
GLOSSARY = [
    ("Image", "A frozen, ready-to-run package of your app plus everything it needs. Like a sealed lunch box: open it anywhere and the same meal is inside."),
    ("Layer", "Each build step adds one thin transparent sheet on top of the previous ones. The image is the whole stack of sheets, and every sheet is read-only."),
    ("Cache", "If a sheet and everything under it are unchanged, Docker reuses it instead of rebuilding it. That is why step order matters: slow, rarely-changing steps go first."),
    ("Stage", "A build can have several mini-builds. Only the last stage becomes the image you ship; earlier stages are scaffolding that gets thrown away."),
    ("Container", "A running copy of an image. It adds one thin writable sheet on top; the image itself never changes."),
    ("Tag vs digest", "A tag like python:3.12-slim is a movable label. A digest (sha256:...) is a fingerprint of exact content and can never point to something else."),
]


def _plain(kw: str, a: str, base: str = "") -> str:
    if kw == "FROM":
        toks = [t for t in a.split() if not t.startswith("--")]
        img = toks[0] if toks else a
        _, tag = _repo_tag(img)
        why = ("a very small Linux (about 5 MB)" if "alpine" in img else
               "a trimmed-down Linux with the language preinstalled and the extras removed" if "slim" in img else
               "a stock Linux image with the language preinstalled")
        warn = " Warning: 'latest' / no tag means the starting point silently changes over time." if tag in (None, "latest") else ""
        return f"Start from {img}: {why}.{warn}"
    if kw == "RUN":
        if re.search(r"apt(-get)?\s+.*install", a):
            pk = re.findall(r"install\s+(?:-\S+\s+)*([^&|;]+)", a)
            pk = " ".join(t for t in (pk[0].split() if pk else []) if not t.startswith("-"))
            return f"Install system programs ({pk or 'see command'}) using Debian's package manager." + (
                " Extra 'recommended' packages are skipped and the download lists are deleted to keep the layer small." if "--no-install-recommends" in a and "/var/lib/apt/lists" in a else "")
        if re.search(r"pip3?\s+install", a):
            return "Install the Python libraries the app depends on."
        if re.search(r"useradd|adduser", a):
            return "Create a normal user called 'app' with no admin rights, so the app never needs root."
        if "venv" in a:
            return "Create an isolated Python environment (a self-contained folder of libraries) that can be copied between stages."
        return "Run a command while building: " + (a[:90] + "..." if len(a) > 90 else a)
    if kw in ("COPY", "ADD"):
        m = re.search(r"--from=(\S+)", a)
        toks = [t for t in a.split() if not t.startswith("--")]
        if m:
            return f"Take only the finished files from the '{m.group(1)}' stage. The tools used to make them stay behind."
        if toks and toks[0] in (".", "./", "*"):
            return "Copy the app's own source code into the image."
        if toks and "requirements" in toks[0] or toks and "package" in toks[0]:
            return "Copy only the dependency list first, so the slow install step below stays cached when only code changes."
        return f"Copy {toks[0] if toks else 'files'} from your computer into the image."
    simple = {
        "WORKDIR": f"Set the working folder to {a}; later steps run from there.",
        "ENV": "Set environment settings the app reads at run time (no secrets here).",
        "ARG": "Declare a build-time option (visible in image history, so never put secrets here).",
        "USER": ("Run as root (not recommended)." if a.split(":")[0] in ("root", "0") else
             f"From here on run as user id {a}, not root. A number cannot be confused with another user." if a.split(":")[0].isdigit() else
             f"From here on run as '{a}', not root."),
        "EXPOSE": f"Document that the app listens on port {a}. Informational; the port is published when the container starts.",
        "HEALTHCHECK": "Every 10 seconds Docker asks the app 'are you healthy?' and marks the container healthy or unhealthy.",
        "CMD": "The command that starts the app when the container runs.",
        "ENTRYPOINT": "The fixed program that always starts when the container runs.",
        "LABEL": "Attach descriptive metadata (name, source) to the image.",
        "VOLUME": "Declare a folder meant for data that should outlive the container.",
    }
    return simple.get(kw, f"{kw} {a}")


def explain(text: str, sizes: list | None = None, findings: list | None = None) -> dict:
    """Stages -> steps in plain language. sizes (bytes) aligns with the FINAL stage's non-FROM instructions."""
    ins = parse(text)
    sts = stages(ins)
    findings = findings or []
    out = []
    for n, s in enumerate(sts):
        final = n == len(sts) - 1
        steps = []
        first = ins[s["first"]]
        steps.append({"kw": "FROM", "text": f"FROM {first['args']}", "plain": _plain("FROM", first["args"]), "layer": False,
                      "size": None, "line": first["start"] + 1, "issues": _issues(findings, first)})
        for k, x in enumerate(s["ins"]):
            steps.append({"kw": x["kw"], "text": f"{x['kw']} {x['args']}"[:300], "plain": _plain(x["kw"], x["args"]),
                          "layer": x["kw"] in ("RUN", "COPY", "ADD"),
                          "size": sizes[k] if final and sizes and k < len(sizes) else None,
                          "line": x["start"] + 1, "issues": _issues(findings, x)})
        out.append({"name": s["alias"] or (f"stage {n + 1}" if len(sts) > 1 else "image"), "base": s["base"],
                    "final": final, "discarded": not final, "steps": steps})
    return {"stages": out, "glossary": [{"term": t, "text": d} for t, d in GLOSSARY],
            "multistage": len(sts) > 1}


def _issues(findings: list, x: dict) -> list[dict]:
    return [{"rule": f["rule"], "severity": f["severity"], "msg": f["msg"]} for f in findings
            if f.get("file") == "Dockerfile" and x["start"] + 1 <= f["line"] <= x["end"] + 1]
