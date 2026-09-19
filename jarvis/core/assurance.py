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
    'sensor_integrity': ('partial', 'native sequence/digest replay checks, continuous-coverage cursors, receipts and watchdogs', 'Independent authenticated sensors and anti-replay not fully validated'),
    'continuous_attestation': ('unverified', 'security posture observations', 'No validated TPM quote/PCR trust chain'),
    'component_isolation': ('partial', 'fixed response action registry', 'Observer and responder privilege separation incomplete'),
    'forensic_storage': ('partial', 'hash-chained temporal segments, evidence cases and response intent records', 'Encrypted storage, external integrity anchors and crash rollback incomplete'),
    'temporal_correlation': ('partial', 'globally sequenced native events, process lineage, incidents and snapshot reconciliation', 'Windows process reconciliation only; attack-sequence and cross-layer coverage incomplete'),
    'forge': ('partial', 'jarvis.lab scenarios', 'No full directive scenario/latency/containment validation'),
    'performance': ('unverified', 'scheduler and resource observations', 'No complete measured CPU/RAM/IO/battery/latency budget'),
    'supply_chain': ('partial', 'standard-library Python runtime', 'Signed reproducible releases and complete SBOM validation unverified'),
    'recovery': ('partial', 'action undo, fresh repair observations and read-only interrupted-action reconciliation', 'No full restart/power-loss recovery validation'),
}


def report():
    return {
        'policy_version': POLICY_VERSION,
        'scope': 'engineering register; not a live security or compromise verdict',
        'complete': False,
        'absence_of_alerts_proves_safety': False,
        'capabilities': {
            name: {'implementation': status, 'basis': basis, 'blind_spot': gap,
                   'live_telemetry': 'unverified', 'last_validation': None,
                   'detection_latency_ms': None, 'intervention_latency_ms': None,
                   'validated_containment': False}
            for name, (status, basis, gap) in CAPABILITIES.items()
        },
    }
