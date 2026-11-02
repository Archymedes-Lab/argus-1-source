"""Fixed PMF metadata only; advisory, never a pricing, outreach or launch decision.

Narrow Jev questions about the riskiest assumption behind the PMF bet chosen on
2026-11-02 (PMF-2026-11.md): CDM committed the baseline (free server edition)
and picked `observed_audit` (one-week observed server review for small agencies)
as the explore candidate. No lead, company, person, URL or evidence is sent:
only aggregate counts and the shape of the offer. Two independent question sets:
`bet` (before building) and `review` (after building the report slice).
"""
import json

from jarvis.response import jev

STATE = {
    'goal': 'get the first paying user for a local security monitor without any protection claim',
    'facts': {
        'register': '54 capabilities: 25 partial, 29 unverified, none live-tested',
        'installs': 'never installed outside the developer machine; VM harness 16 of 16 passed',
        'buyers': '20 prospect and 10 agency search results judged paying tier; '
                  '9 self-hoster results, none paying; nobody contacted yet',
        'status_quo': 'freelance one-server audits from about 199 USD; free scanners',
        'offer': 'one-week observed server review: founder installs the server edition with '
                 'the client, report of operational findings and blind spots stays on their '
                 'server and says it is not an audit or certification; fixed fee, deposit first',
        'cdm': 'commit free server edition (baseline); explore the observed review; '
               'demand score 0.85 vs 0.38 for the baseline',
    },
}
QUESTIONS = {
    'agency_pays': {'type': 'noul', 'instructions':
        'Will at least one small software agency pay a fixed fee for this one-week observed '
        'server review within six weeks of owner-approved outreach to about 15 prospects?',
        'criteria': {'true': 'Yes, likely', 'false': 'No, unlikely'}},
    'riskiest': {'type': 'choice', 'instructions':
        'Which assumption behind this offer is most likely to be false?',
        'criteria': {'will_pay': 'Agencies will pay for a review that makes no protection claim',
                     'access': 'Agencies will let an outside founder install software on client servers',
                     'clean_install': 'The native build installs and removes cleanly on a customer server',
                     'week_value': 'One week of observation finds something worth the fee',
                     'founder_time': 'The founder can deliver reviews without stalling the product'}},
    'review_not_audit': {'type': 'noul', 'instructions':
        'Does naming it a review, with a line saying it is not an audit or certification, '
        'keep buyers from reading it as a security guarantee?',
        'criteria': {'true': 'Yes, mostly', 'false': 'No, buyers will still read it as assurance'}},
    'price_band': {'type': 'choice', 'instructions':
        'Which fixed fee per server for the first three reviews best tests willingness to pay?',
        'criteria': {'free_pilot': 'Free pilot, ask for a testimonial',
                     'under_200': 'Under 200 USD',
                     'b200_500': '200 to 500 USD',
                     'b500_1000': '500 to 1000 USD',
                     'over_1000': 'Over 1000 USD'}},
    'install_gate': {'type': 'noul', 'instructions':
        'Is it acceptable to install on a paying customer server before a clean install, '
        'upgrade and removal of the native build has been measured on fresh VMs?',
        'criteria': {'true': 'Yes', 'false': 'No, measure clean VMs first'}},
}
REVIEW_STATE = {
    'goal': 'a local server review report that never claims more than the coverage register',
    'design': {
        'scope': 'read-only command; runs the existing per-area server audits once and renders '
                 'one report; no network; file written owner-only; JSON and text',
        'continuity': 'a section whose audit fails or is unavailable is listed as not observed '
                      'with the error class, never dropped',
        'claims': 'coverage and limits come from the register; status words fixed; render '
                  'refuses overclaim phrases and outcome verbs; says it is not an audit',
        'privacy': 'finding detail is bounded and passed through the secret redactor; counts '
                   'and titles only for appcode secrets',
        'bounds': 'at most 40 findings per section and a fixed line cap',
        'tests': 'success, failing section, empty store, overclaim, privacy, bounds, read-only',
    },
}
REVIEW_QUESTIONS = {
    'not_observed_honest': {'type': 'noul', 'instructions':
        'Is listing a failed section as not observed, with only its error class, honest enough '
        'for a paying client report?',
        'criteria': {'true': 'Yes', 'false': 'No, it needs more detail'}},
    'redaction_enough': {'type': 'noul', 'instructions':
        'Is passing finding detail through a secret redactor with a length cap enough to keep '
        'credentials out of a report that the client may forward?',
        'criteria': {'true': 'Yes', 'false': 'No, detail should be dropped for secret findings'}},
    'top_gap': {'type': 'choice', 'instructions':
        'Which validation gap in this report matters most before the first paid review?',
        'criteria': {'native_vm': 'Generate it from the native build on a fresh VM after a week',
                     'reader_test': 'A real agency lead reads it and says what it means to them',
                     'noise': 'Alert noise on a fresh host inflates the findings',
                     'wording': 'Engineer-written register limits read oddly to clients'}},
}
if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['review']:
        STATE, QUESTIONS = REVIEW_STATE, REVIEW_QUESTIONS
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
