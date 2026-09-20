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
    'system_state_graph': ('partial', 'ProcessGuid lineage and conservative snapshot/event reconciliation', 'Windows process state only; no complete cross-layer causal graph'),
    'behavioral_physics': ('partial', 'resourcewatch', 'Hardware counters and robust multivariate validation incomplete'),
    'sensor_integrity': ('partial', 'native sequence/digest replay checks, manifest-addressed spool reads, process-deadlined ingestion, continuous-coverage cursors, receipts, freshness budgets, leases and supervised recovery watchdogs', 'Independent authenticated sensors and anti-replay not fully validated; Windows-native deployment and DrvFS failure recovery require live validation'),
    'continuous_attestation': ('unverified', 'security posture observations', 'No validated TPM quote/PCR trust chain'),
    'component_isolation': ('partial', 'fixed response action registry', 'Observer and responder privilege separation incomplete'),
    'forensic_storage': ('partial', 'hash-chained temporal segments, evidence cases and response intent records', 'Encrypted storage, external integrity anchors and crash rollback incomplete'),
    'temporal_correlation': ('partial', 'globally sequenced native events, process lineage, incidents and snapshot reconciliation', 'Windows process reconciliation only; attack-sequence and cross-layer coverage incomplete'),
    'forge': ('partial', 'jarvis.lab scenarios', 'No full directive scenario/latency/containment validation'),
    'performance': ('unverified', 'per-subsystem scheduler duty cycle, process/RAM/database profiling and read-only accelerator inventory', 'No complete measured CPU/RAM/IO/battery/latency budget or validated CPU-vs-GPU model benchmark'),
    'supply_chain': ('partial', 'standard-library Python runtime', 'Signed reproducible releases and complete SBOM validation unverified'),
    'recovery': ('partial', 'action undo, fresh repair observations and read-only interrupted-action reconciliation', 'No full restart/power-loss recovery validation'),
    'self_improvement': ('partial', 'human-gated fix proposals: deterministic daemon scan, rate-limited proposal email, explicit terminal or localhost-dashboard approval, test-gated apply with revert', 'No autonomous code execution; opencode drafts and Ollama notes are advisory only and email replies cannot approve'),
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
