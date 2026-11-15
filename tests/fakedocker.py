"""Scriptable stand-in for the docker CLI (run_fn signature). Records every call."""
import json

from deploy_agent.runner import Result


class FakeDocker:
    def __init__(self, **o):
        self.calls, self.builds = [], 0
        self.o = {"daemon": True, "build_rc": 0, "health": "healthy", "user": "app", "uid": "1000", "exit": "0", "rebuild_cached": True,
                  "port": "127.0.0.1:49153", **o}

    def __call__(self, argv, cwd=None, env=None, timeout=0, check=True):
        self.calls.append(list(argv))
        a, o = argv, self.o
        ok = lambda out="", err="": Result(0, out, err)
        if a[0] == "docker":
            sub = a[1]
            if sub == "info":
                return ok("27.0.3") if o["daemon"] else Result(1, "", "Cannot connect to the Docker daemon")
            if sub == "build":
                self.builds += 1
                if o["build_rc"]:
                    return Result(o["build_rc"], "", "#5 ERROR: failed to solve")
                cached = o["rebuild_cached"] and self.builds > 1
                lines = ["#4 [1/3] FROM python:3.12-slim", "#5 [2/3] RUN pip install", "#5 CACHED" if cached else "#5 DONE 1.2s",
                         "#6 [3/3] COPY . .", "#6 CACHED" if cached else "#6 DONE 0.1s"]
                return ok("", "\n".join(lines))
            if sub == "image":
                return ok(json.dumps([{"Id": "sha256:" + "a" * 64, "Size": 61_000_000, "RootFS": {"Layers": ["x"] * 5}, "Os": "linux",
                                       "Architecture": "arm64", "RepoDigests": [], "Config": {"User": o["user"], "Healthcheck": {"Test": ["CMD"]},
                                       "ExposedPorts": {"8080/tcp": {}}, "Cmd": ["python", "server.py"]}}]))
            if sub == "history":
                return ok("\n".join(json.dumps({"CreatedBy": c, "Size": s}) for c, s in
                                    [('CMD ["python" "server.py"]', "0"), ("COPY . . # buildkit", "1200"), ("RUN pip install # buildkit", "5000000")]))
            if sub == "run":
                return ok("cid123")
            if sub == "port":
                return ok(o["port"]) if o["port"] else Result(1, "", "no public port")
            if sub == "inspect":
                fmt = a[3] if a[2] == "-f" else ""
                if "Health.Status" in fmt:
                    return ok(f"{o['health']}|true")
                if "Config.User" in fmt:
                    return ok(o["user"])
                if "ExitCode" in fmt:
                    return ok(o["exit"])
            if sub == "exec":
                return ok(o["uid"])
            if sub in ("stop", "rm", "logs"):
                return ok("listening on :8080\nstopped cleanly")
        if a[0] == "trivy" and "image" in a:
            if "cyclonedx" in a:
                out = a[a.index("--output") + 1]
                open(out, "w").write(json.dumps({"components": [{"name": "x"}] * 3}))
                return ok()
            return ok(json.dumps({"Results": [{"Vulnerabilities": o.get("vulns", [])}]}))
        if a[0] == "trivy" and "config" in a:
            return ok(json.dumps({"Results": []}))
        if a[0] == "hadolint":
            return ok(json.dumps(o.get("hadolint", [])))
        return Result(127, "", f"unexpected: {a}")

    def subs(self, name):
        return [c for c in self.calls if c[0] == "docker" and c[1] == name]
