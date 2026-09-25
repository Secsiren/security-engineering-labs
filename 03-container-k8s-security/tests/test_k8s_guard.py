import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "checker"))
import k8s_guard as g  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
GOOD = ROOT / "k8s" / "good"
BAD = ROOT / "k8s" / "bad"


def rules(findings, min_sev="LOW"):
    return {f.rule for f in findings if g.SEV[f.severity] >= g.SEV[min_sev]}


def test_hardened_manifests_have_no_findings():
    assert g.scan(GOOD) == []
    assert g.main([str(GOOD)]) == 0


def test_insecure_manifest_fails_build():
    assert g.main([str(BAD)]) == 1


def test_insecure_manifest_triggers_every_expected_rule():
    found = rules(g.scan(BAD))
    expected = {"K001", "K002", "K003", "K004", "K005", "K006", "K007",
                "K008", "K009", "K010", "K011", "K012", "K013"}
    assert expected <= found


def test_docker_socket_mount_is_critical():
    crit = [f for f in g.scan(BAD) if f.rule == "K011"]
    assert crit and crit[0].severity == "CRITICAL"


def test_privileged_is_critical():
    assert any(f.rule == "K005" and f.severity == "CRITICAL" for f in g.scan(BAD))


def test_tag_pinned_image_is_only_low(tmp_path):
    m = tmp_path / "pod.yaml"
    m.write_text("""
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: x}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: c
      image: nginx:1.27.1
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      resources: {limits: {cpu: 100m, memory: 64Mi}}
""")
    f = g.scan(m)
    assert [(x.rule, x.severity) for x in f] == [("K006", "LOW")]


def test_pod_level_security_context_is_inherited(tmp_path):
    m = tmp_path / "pod.yaml"
    m.write_text("""
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  securityContext: {runAsNonRoot: true}
  containers: [{name: c, image: "a@sha256:abc"}]
""")
    assert "K001" not in rules(g.scan(m))
