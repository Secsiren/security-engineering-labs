# 03 · Container & Kubernetes Security

**Proves:** Certified Container Security Expert (CCSE) and Certified Cloud Native Security Expert (CCNSE) skills: hardening workloads, enforcing Pod Security, default-deny networking and policy-as-code.

**Defence in depth, in three layers**

1. **Build:** the hardened image from [project 01](../01-devsecops-supply-chain) (non-root, slim, scanned with Trivy, SBOM signed).
2. **CI:** [`checker/k8s_guard.py`](checker/k8s_guard.py) fails the pipeline if a manifest breaks the rules below. Trivy config scanning runs as a second opinion.
3. **Cluster admission:** Pod Security Admission (`restricted`) on the namespace, plus [Kyverno policies](policies/kyverno-baseline.yaml) that block anything that bypasses CI.

## Rules

| ID | Severity | Rule | Why it matters |
|---|---|---|---|
| K001 | HIGH | `runAsNonRoot: true` | A container escape as root is a node compromise |
| K002 | HIGH | `allowPrivilegeEscalation: false` | Blocks setuid binaries gaining root |
| K003 | MEDIUM | `readOnlyRootFilesystem: true` | Attackers can't drop tools or modify the app |
| K004 | MEDIUM/HIGH | Drop `ALL` capabilities; never add SYS_ADMIN/NET_ADMIN | Least privilege at kernel level |
| K005 | CRITICAL | No `privileged: true` | Privileged = full host access |
| K006 | HIGH/LOW | Image pinned by digest (tag = LOW, `latest` = HIGH) | What was scanned is what runs |
| K007 | MEDIUM | CPU/memory limits set | Noisy-neighbour and DoS protection |
| K008 | HIGH | No hostNetwork/hostPID/hostIPC | Keeps pods out of node namespaces |
| K009 | MEDIUM | seccomp `RuntimeDefault` | Blocks dangerous syscalls |
| K010 | LOW | Don't auto-mount service account token | No Kubernetes API credentials unless needed |
| K011 | HIGH/CRITICAL | No hostPath (docker.sock = CRITICAL) | Mounting docker.sock = root on the node |
| K012 | HIGH | Namespace enforces Pod Security `restricted` | Cluster-side guarantee |
| K013 | HIGH | Default-deny NetworkPolicy (ingress + egress) | Stops lateral movement |

## Evidence

```text
$ python checker/k8s_guard.py k8s/good
0 findings, 0 at or above HIGH -> PASS

$ python checker/k8s_guard.py k8s/bad
[CRITICAL] K011 Deployment/legacy/legacy-app: hostPath volume /var/run/docker.sock
[CRITICAL] K005 Deployment/legacy/legacy-app:app: privileged container
[HIGH    ] K012 Namespace/legacy: Pod Security 'restricted' not enforced
...
15 findings, 10 at or above HIGH -> FAIL
```

```bash
pytest -q    # 7 passed
```

*Lab manifests only. The image digest is illustrative.*
