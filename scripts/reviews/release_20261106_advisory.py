"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'bring the signed ARGUS-INSTINCT release up to date with work that never reached main, '
            'without weakening any invariant main already enforces',
    'merged_onto_main': {
        'stripe_fleet': 'licence Worker: fleet and team seat quantities, Desktop monthly, promotion codes',
        'pr10_plain_language': 'plain-language wording, $15 month / $79 year local plans, live Geo and '
                               'World views, a second pinned releaser key; billing conflicts resolved '
                               'toward main (no payment lock reintroduced)',
        'bugcheck': 'stop errors named by the failing layer (hypervisor, kernel, driver)',
        'restart_autopsy': 'new 300 s job attributing every daemon stop to an actor, root-owned restart '
                           'gate installer; replayed on 23 recorded stops, never soaked live',
        'osquery_cross_view': 'optional second reader when the operator installed osquery; never '
                              'installs it; measured only in a container',
        'ollama_install': 'download and install Ollama only after explicit owner approval',
    },
    'invariants': [
        'a licence never gates protection (existing test kept green)',
        'every new capability declared unverified in the assurance register, gap counts raised, '
        'nothing promoted',
        'new jobs registered in the mechanism registry and lanes',
    ],
    'checks': 'full unit suite and static gate on the merged tree; then a host attestation, a CI dry '
              'run including clean Windows install tests, and the releaser signature',
    'not_done': ['no live soak of restart autopsy or osquery', 'translated pricing sentence still says '
                 'the licence "unlocks ARGUS-INSTINCT"'],
}
QUESTIONS = {
    'riskiest': {'type': 'choice', 'instructions':
        'Which merged item carries the most risk of a user-visible regression in this release?',
        'criteria': {'stripe_fleet': 'Worker fleet/team quantities and promotion codes',
                     'pr10_plain_language': 'Plain-language, pricing and Geo/World merge',
                     'restart_autopsy': 'Restart autopsy job and restart gate',
                     'osquery_cross_view': 'osquery cross-view',
                     'ollama_install': 'Ollama installer',
                     'bugcheck': 'Stop-error naming'}},
    'ship_unsoaked': {'type': 'noul', 'instructions':
        'Is it reasonable to ship new detection jobs that are declared unverified and never soaked '
        'live, given the suite, the CI install tests and the honest assurance labels?',
        'criteria': {'true': 'Reasonable to ship labelled as unverified',
                     'false': 'Hold them until soaked'}},
    'next_gate': {'type': 'choice', 'instructions':
        'After the suite and the static gate pass, which validation adds the most before tagging?',
        'criteria': {'dry_run': 'The CI dry run with clean Windows install tests',
                     'live_readback': 'Deploy here and read back against a written baseline',
                     'manual_review': 'Human review of the merged diff',
                     'none': 'No further validation needed'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
