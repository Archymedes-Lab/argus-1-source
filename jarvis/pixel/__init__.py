"""Who can watch this machine, and does it phone home when you read things?

Three surfaces, one question each:

  * `screen` — can anything read the display, and is the display protected
    from the things that can?
  * `mail`   — do messages carry tracking pixels, and does the mail client
    load them before you decide to open anything?
  * `web`    — is the browser configured to refuse beacons and the
    third-party cookies that make them useful?
"""

from .common import SEV_ORDER, finding, sort_findings
from .run import audit
from . import mail, screen, web

__all__ = ["SEV_ORDER", "audit", "finding", "sort_findings",
           "mail", "screen", "web"]
