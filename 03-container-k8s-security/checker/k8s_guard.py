"""k8s_guard: a small policy-as-code checker for Kubernetes manifests.

Checks a folder of YAML manifests against the Pod Security "restricted"
profile plus common hardening rules (image pinning, resource limits,
host namespaces, hostPath, default-deny NetworkPolicy). Designed to run in CI
before `kubectl apply`, so insecure workloads fail the build instead of
reaching the cluster.

Usage: python checker/k8s_guard.py k8s/good [--fail-on HIGH]
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW", "ALL"}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    obj: str
    message: str


def load_docs(path: Path) -> list[dict]:
    files = [path] if path.is_file() else sorted(path.rglob("*.y*ml"))
    docs = []
    for f in files:
        docs += [d for d in yaml.safe_load_all(f.read_text()) if isinstance(d, dict)]
    return docs


def pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec", {})
    if kind == "CronJob":
        return doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    if kind in WORKLOAD_KINDS:
        return doc.get("spec", {}).get("template", {}).get("spec", {})
    return None


def _name(doc: dict) -> str:
    md = doc.get("metadata", {})
    return f"{doc.get('kind')}/{md.get('namespace', 'default')}/{md.get('name', '?')}"


def check_workload(doc: dict) -> list[Finding]:
    spec = pod_spec(doc) or {}
    obj = _name(doc)
    out: list[Finding] = []
    psc = spec.get("securityContext", {}) or {}

    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(flag):
            out.append(Finding("K008", "HIGH", obj, f"{flag}: true shares the node's namespace"))
    for v in spec.get("volumes", []) or []:
        if "hostPath" in v:
            sev = "CRITICAL" if "docker.sock" in str(v["hostPath"].get("path", "")) else "HIGH"
            out.append(Finding("K011", sev, obj, f"hostPath volume {v['hostPath'].get('path')}"))
    if spec.get("automountServiceAccountToken") is not False:
        out.append(Finding("K010", "LOW", obj, "service account token is auto-mounted"))

    for c in (spec.get("containers", []) or []) + (spec.get("initContainers", []) or []):
        cname = f"{obj}:{c.get('name')}"
        sc = c.get("securityContext", {}) or {}
        run_non_root = sc.get("runAsNonRoot", psc.get("runAsNonRoot"))
        if run_non_root is not True:
            out.append(Finding("K001", "HIGH", cname, "runAsNonRoot is not true"))
        if sc.get("allowPrivilegeEscalation") is not False:
            out.append(Finding("K002", "HIGH", cname, "allowPrivilegeEscalation is not false"))
        if sc.get("readOnlyRootFilesystem") is not True:
            out.append(Finding("K003", "MEDIUM", cname, "root filesystem is writable"))
        caps = sc.get("capabilities", {}) or {}
        if "ALL" not in (caps.get("drop") or []):
            out.append(Finding("K004", "MEDIUM", cname, "capabilities not dropped (drop: [ALL])"))
        added = set(caps.get("add") or []) & DANGEROUS_CAPS
        if added:
            out.append(Finding("K004", "HIGH", cname, f"dangerous capabilities added: {sorted(added)}"))
        if sc.get("privileged"):
            out.append(Finding("K005", "CRITICAL", cname, "privileged container"))
        image = c.get("image", "")
        if "@sha256:" not in image:
            tag = image.rsplit(":", 1)[1] if ":" in image.split("/")[-1] else ""
            if tag in ("", "latest"):
                out.append(Finding("K006", "HIGH", cname, f"image not pinned: {image}"))
            else:
                out.append(Finding("K006", "LOW", cname, f"image pinned by tag, not digest: {image}"))
        limits = (c.get("resources", {}) or {}).get("limits", {}) or {}
        if not {"cpu", "memory"} <= set(limits):
            out.append(Finding("K007", "MEDIUM", cname, "cpu/memory limits missing"))
        seccomp = (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type")
        if seccomp not in ("RuntimeDefault", "Localhost"):
            out.append(Finding("K009", "MEDIUM", cname, "no seccomp profile"))
    return out


def check_cluster(docs: list[dict]) -> list[Finding]:
    """Namespace-level rules: PSA label and default-deny NetworkPolicy."""
    out: list[Finding] = []
    namespaces = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "Namespace"}
    denied = {
        d.get("metadata", {}).get("namespace", "default")
        for d in docs
        if d.get("kind") == "NetworkPolicy"
        and d.get("spec", {}).get("podSelector") == {}
        and {"Ingress", "Egress"} <= set(d.get("spec", {}).get("policyTypes", []))
    }
    for name, ns in namespaces.items():
        labels = ns.get("metadata", {}).get("labels", {}) or {}
        if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
            out.append(Finding("K012", "HIGH", f"Namespace/{name}", "Pod Security 'restricted' not enforced"))
        if name not in denied:
            out.append(Finding("K013", "HIGH", f"Namespace/{name}", "no default-deny NetworkPolicy"))
    return out


def scan(path: Path) -> list[Finding]:
    docs = load_docs(path)
    findings = check_cluster(docs)
    for d in docs:
        if d.get("kind") in WORKLOAD_KINDS:
            findings += check_workload(d)
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--fail-on", default="HIGH", choices=list(SEV))
    args = ap.parse_args(argv)
    findings = scan(Path(args.path))
    threshold = SEV[args.fail_on]
    for f in sorted(findings, key=lambda x: -SEV[x.severity]):
        print(f"[{f.severity:8}] {f.rule} {f.obj}: {f.message}")
    blocking = [f for f in findings if SEV[f.severity] >= threshold]
    print(f"{len(findings)} findings, {len(blocking)} at or above {args.fail_on} -> "
          f"{'FAIL' if blocking else 'PASS'}")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
