"""Conservative assurance claims. Configuration and passing health are not proof."""
POLICY_VERSION = '2026-09-19'

# This register deliberately grants no deployment/containment validation from
# source inspection. A future evidence importer must validate signed receipts.
CAPABILITIES = {
    'human_safety': ('partial', 'response actions and bounded repairs', 'No complete essential-service dependency model'),
    'online_guardian': ('partial', 'internetwatch and threat intelligence', 'No synchronous browser credential/payment/OAuth interception'),
    'browser_privacy_veil': ('partial', 'opt-in metadata-only browser sensor and deterministic Veil correlation', 'No installed/attested browser integration, CNAME resolution, or validated browser-side blocking'),
    'credential_guardian': ('partial', 'secret scanning and credential access collectors', 'No complete secret-egress prevention'),
    'download_provenance': ('unverified', 'host collectors', 'Extraction-to-execution provenance not established'),
    'system_state_graph': ('partial', 'ProcessGuid lineage, conservative snapshot/event reconciliation, deterministic posture debt and conditional remediation projections, bounded repair audit state, and repeated-sample sustained-health verification', 'No complete cross-layer causal graph, broad verified remediation orchestration, reboot-cycle sustained-health proof, or long-duration soak evidence'),
    'behavioral_physics': ('partial', 'resourcewatch', 'Hardware counters and robust multivariate validation incomplete'),
    'sensor_integrity': ('partial', 'native sequence/digest replay checks, manifest-addressed spool reads, process-deadlined ingestion, continuous-coverage cursors, snapshot/event perception states, live-validated elevated Sysmon policy export (2026-09-22: running config hash equals windows-sysmon/jarvis-windows-baseline.xml, ProcessCreate unfiltered), fresh Windows reconciliation and an EventLogReader boot-pressure probe (4.3s measured unelevated, was 230s via Get-WinEvent); receipts, freshness budgets, leases and supervised recovery watchdogs', 'Independent authenticated sensors and anti-replay remain incomplete; boot 94 still overflowed the driver queue 46s after boot, under the previous policy, dropping 82 ProcessCreate and 64784 RegistryEvent records, and whether the new baseline prevents boot-time overflow is unmeasured until a reboot; no export of the pre-change policy was preserved; the faster pressure probe needs a broker re-install before it runs elevated'),
    'continuous_attestation': ('unverified', 'security posture observations', 'No validated TPM quote/PCR trust chain'),
    'component_isolation': ('partial', 'fixed response action registry', 'Observer and responder privilege separation incomplete'),
    'forensic_storage': ('partial', 'authoritative Python hash-chained temporal event log plus an independently durable Rust gzip segment store with locked writers, atomic segment commits and full verification, fed by a governed bounded mirror job: events carry their authoritative source_seq, the store is its own cursor, ingest is all-or-nothing, budgeted pruning keeps the header chain and a store cursor behind the recorded one pauses mirroring as tampering evidence (unit-tested; live only after the daemon next restarts); evidence cases and response intent records', 'The Rust mirror trails the authoritative log by up to one job interval plus backlog, is not an atomic mirror, and runs under the same account, so it is not tamper-independent; retention gaps before mirroring are counted, not recoverable; encrypted storage, external integrity anchors and rollback detection remain incomplete'),
    'temporal_correlation': ('partial', 'globally sequenced native events, multi-category temporal projection (process/network/file/registry/driver/ipc/wmi/malware/protection/task/sensor), event-consumed detectors, process lineage, incidents and snapshot reconciliation clamped to the current boot by its kernel-lifetime processes', 'Windows process reconciliation only; the sensor labels records with the boot current at read time, so the prior boot shutdown tail is excluded at reconciliation, not at ingest; kernel minimal processes (Registry, Memory Compression, vmmem) have no start event and stay unknown; attack-sequence and cross-layer coverage incomplete'),
    'forge': ('partial', 'jarvis.lab scenarios', 'No full directive scenario/latency/containment validation'),
    'performance': ('partial', 'per-subsystem scheduler duty cycle, process/RAM/database profiling, shared process/socket providers, optional Rust metrics/governance and durable-store bridge, plus hourly-validated OpenVINO GPU execution of bounded deterministic graphs (GPU.0, CPU-reference cross-checked)', 'No complete measured CPU/RAM/IO/battery/latency budget, authoritative Rust sensor-ingest integration or comparative CPU-vs-GPU throughput benchmark'),
    'supply_chain': ('partial', 'standard-library Python runtime', 'Signed reproducible releases and complete SBOM validation unverified'),
    'recovery': ('partial', 'action undo, fresh repair observations and read-only interrupted-action reconciliation', 'No full restart/power-loss recovery validation'),
    'self_improvement': ('partial', 'human-gated fix proposals: deterministic daemon scan, bounded validated Ollama directives, OpenCode patch drafting, advisory Jev assessments (Tier-2, human-gated, offline-safe), separate investigation and exact-patch authorization, test-gated apply with revert', 'No autonomous code execution; model directives remain untrusted, application stays human-authorized, and email replies cannot approve'),
}


OBSERVATION_REQUIREMENTS = {
    # These are liveness/visibility signals only.  They never upgrade a
    # capability's implementation or containment validation claim.
    'sensor_integrity': ('scan', 'bridge', 'sysmon', 'native'),
    'system_state_graph': ('scan', 'sysmon'),
    'temporal_correlation': ('sysmon', 'native'),
    'online_guardian': ('internet',),
    'browser_privacy_veil': ('veil',),
    'credential_guardian': ('secrets',),
    'behavioral_physics': ('resources',),
}


def _implementation_weight(status):
    """Conservative evidence weight of an implementation claim."""
    return {'partial': 0.5, 'unverified': 0.0}.get(status, 1.0)


def _observation_factor(name, observations):
    """Fraction of a capability's required sources currently observable.

    Proportional, and conservative at the edges: a mapping gap scores the
    same as blindness (it is, for assurance purposes), and a source that is
    stale or partial earns nothing — only 'complete' observations count.
    """
    required = OBSERVATION_REQUIREMENTS.get(name)
    if not required:
        return 0.0
    states = [observations.get(source, {}).get('status', 'not_reporting')
              for source in required]
    return sum(1.0 for state in states if state == 'complete') / len(required)


def score(observations=None):
    """Assurance 0-100: how much evidence supports trusting JARVIS itself.

    Deliberately separate from the machine's protection-health score. A
    machine can score 100 while JARVIS is missing release-critical
    capabilities; this number says so instead of hiding it. Every capability
    is weighted by its implementation claim and by how much of its telemetry
    is observable right now; 100 is unreachable while the register holds
    'partial' and 'unverified' entries, which is the point.
    """
    observations = observations or {}
    weights = []
    for name, (status, _basis, _gap) in CAPABILITIES.items():
        weights.append(_implementation_weight(status)
                       * _observation_factor(name, observations))
    return round(100 * sum(weights) / len(weights)) if weights else 0


def _telemetry(name, observations):
    required = OBSERVATION_REQUIREMENTS.get(name)
    if not required:
        return 'unverified'
    states = [observations.get(source, {}).get('status', 'not_reporting') for source in required]
    if all(state == 'complete' for state in states):
        return 'current'
    if any(state in ('partial', 'stale', 'unavailable') for state in states):
        return 'degraded'
    return 'not_reporting'


def report(observations=None):
    observations = observations or {}
    return {
        'policy_version': POLICY_VERSION,
        'scope': 'engineering register; not a live security or compromise verdict',
        'complete': False,
        'absence_of_alerts_proves_safety': False,
        'score': score(observations),
        'score_definition': 'weighted evidence of trust in JARVIS itself; '
                            'not machine protection health',
        'capabilities': {
            name: {'implementation': status, 'basis': basis, 'blind_spot': gap,
                   'live_telemetry': _telemetry(name, observations), 'last_validation': None,
                   'detection_latency_ms': None, 'intervention_latency_ms': None,
                   'validated_containment': False}
            for name, (status, basis, gap) in CAPABILITIES.items()
        },
    }
