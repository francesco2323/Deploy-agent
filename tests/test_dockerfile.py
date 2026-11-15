from types import SimpleNamespace

from deploy_agent import dockerfile as df

BAD = """FROM python:latest
RUN apt-get update && apt-get install -y curl
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8080
CMD python server.py
"""
CTX = {"port": 8080, "health_path": "/healthz", "name": "x"}
NAMED_USER = """FROM python:3.12-slim
RUN groupadd --system app && useradd --system --gid app --no-create-home app
USER app
CMD ["python", "server.py"]
"""
FIXTURE = {"user-numeric": NAMED_USER}  # fixers whose trigger is not in BAD


def rules(t, ign=True):
    return {f["rule"] for f in df.lint(t, ign)}


def test_lint_finds_every_planted_problem():
    assert rules(BAD, ign=False) == {"CAP001", "CAP002", "CAP003", "CAP004", "CAP005", "CAP006", "CAP007", "CAP008", "CAP009"}


def test_each_fixer_clears_its_rule_and_is_idempotent():
    for fid, ids, _t, _w, fn in df.FIXES:
        src = FIXTURE.get(fid, BAD)
        out = fn(src, CTX)
        assert out and out != src, fid
        assert not (rules(out) & {i for i in ids if i.startswith("CAP")}) or fid in ("non-root", "healthcheck"), fid
        assert fn(out, CTX) in (None, out), f"{fid} not idempotent"


def test_full_chain_reaches_clean_multistage():
    t = BAD
    for _ in range(10):
        for fid, ids, _t, _w, fn in df.FIXES:
            n = fn(t, CTX)
            if n and n != t:
                t = n
                break
        else:
            break
    assert rules(t) == {"CAP008"}
    t = df.fix_multistage(t, CTX)
    assert rules(t) == set()
    assert t.count("FROM ") == 2 and "USER 10001:10001" in t and "HEALTHCHECK" in t and 'CMD ["python", "server.py"]' in t
    assert df.fix_multistage(t, CTX) is None  # already multi-stage


def test_pin_leaves_unknown_and_stage_refs_alone():
    t = "FROM mycorp/base\nFROM base2:latest AS x\nFROM x\n"
    assert df.fix_pin(t, CTX) == t
    assert df.fix_pin("FROM python\n", CTX) == "FROM python:3.12-slim\n"


def test_shell_operators_are_not_guessed():
    t = "FROM python:3.12-slim\nCMD python a.py && echo done\n"
    assert df.fix_cmd(t, CTX) in (None, t)
    assert df.fix_cmd("FROM x:1\nCMD sh -c 'a && b'\n", CTX).endswith('CMD ["sh", "-c", "a && b"]\n')


def test_secrets_flagged_not_fixed():
    t = "FROM python:3.12-slim\nENV API_TOKEN=abc123\nADD http://x/y.sh /y.sh\nUSER app\nHEALTHCHECK CMD true\n"
    r = [f for f in df.lint(t, True) if f["rule"] == "CAP010"]
    assert len(r) == 2


def test_explainer_plain_language_and_stages():
    t = df.fix_multistage(BAD.replace("python:latest", "python:3.12-slim"), CTX)
    e = df.explain(t, sizes=[0] * 99, findings=[])
    assert [s["discarded"] for s in e["stages"]] == [True, False] and e["multistage"]
    plain = " ".join(x["plain"] for s in e["stages"] for x in s["steps"])
    assert "thrown away" not in plain and "finished files" in plain and "normal user" in plain
    assert e["stages"][0]["steps"][0]["kw"] == "FROM" and all(x["size"] is None for x in e["stages"][0]["steps"])
    single = df.explain(BAD, findings=df.lint(BAD, True))
    assert not single["multistage"] and any(x["issues"] for x in single["stages"][0]["steps"])


def test_unused_debug_tools_are_dropped_only_when_nothing_uses_them():
    out = df.fix_apt_unused(BAD, CTX)
    assert "apt-get" not in out and "curl" not in out and "pip install" in out
    used = BAD.replace("EXPOSE 8080\n", "EXPOSE 8080\nHEALTHCHECK CMD curl -f http://localhost:8080/\n")
    assert df.fix_apt_unused(used, CTX) is None  # the HEALTHCHECK needs curl
    assert df.fix_apt_unused(BAD.replace("-y curl", "-y curl ca-certificates"), CTX) is None  # all-or-nothing: DL3008 would not clear
    builder_only = 'FROM python:3.12-slim AS b\nRUN apt-get update && apt-get install -y curl\nFROM python:3.12-slim\nCMD ["x"]\n'
    assert df.fix_apt_unused(builder_only, CTX) is None  # thrown-away stage
    assert "apt-get" not in df.fix_apt_unused(df.fix_apt(BAD, CTX), CTX)  # also after the apt-clean fix rewrote it


def test_numeric_user_rewrites_only_users_this_dockerfile_creates():
    out = df.fix_user_numeric(NAMED_USER, CTX)
    assert "USER 10001:10001" in out and "--uid 10001" in out and "groupadd --gid 10001" in out
    assert df.fix_user_numeric(out, CTX) is None  # idempotent
    assert df.fix_user_numeric("FROM node:22-slim\nUSER node\n", CTX) is None  # base-image user: its id is never guessed
    assert df.fix_user_numeric("FROM python:3.12-slim\nUSER root\n", CTX) is None
    alpine = "FROM python:3.12-alpine\nRUN addgroup -S app && adduser -S -G app -H app\nUSER app\n"
    a = df.fix_user_numeric(alpine, CTX)
    assert "addgroup -g 10001 -S app" in a and "adduser -u 10001 -S -G app -H app" in a and "USER 10001:10001" in a
    keep = 'FROM python:3.12-slim\nRUN groupadd --gid 2000 app && useradd --uid 2000 --gid app app\nUSER app\n'
    assert df.fix_user_numeric(keep, CTX).endswith("USER 2000:2000\n")  # ids the author chose are kept


def test_generated_users_are_numeric():
    t = df.fix_user('FROM python:3.12-slim\nCMD ["x"]\n', CTX)
    assert "USER 10001:10001" in t and "--uid 10001" in t and "--gid 10001" in t


def test_topology_reads_the_run_time_shape_from_the_dockerfile():
    app = SimpleNamespace(name="a", image="x/a", port=8080, health_path="/healthz")
    t = df.topology(BAD, app)
    assert t["root"] and not t["healthcheck"] and t["shell_form"] and t["volumes"] == [] and t["network"] == "bridge"
    assert t["ports"] == [{"host": 8080, "container": 8080, "exposed": True}] and t["stages"] == 1
    g = 'FROM python:3.12-slim\nVOLUME ["/data", "/cache"]\nEXPOSE 9090\nUSER 10001:10001\nHEALTHCHECK CMD true\nCMD ["python", "server.py"]\n'
    t = df.topology(g, app)
    assert t["volumes"] == ["/data", "/cache"] and not t["root"] and t["healthcheck"] and not t["shell_form"]
    assert t["ports"][0]["exposed"] is False and t["extra_ports"] == [9090] and t["cmd"] == "python server.py"
    assert df.topology("", app)["base"] == ""  # an empty Dockerfile does not crash
