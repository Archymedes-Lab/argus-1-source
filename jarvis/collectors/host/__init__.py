"""Per-host collectors: each gathers a slice of host state into findings."""

from . import accelerator, audiowatch, bootchain, bootintegrity, canary, containers
from . import content, controlwatch, dotnet_posture, firmwareaudit, fridaydefender
from . import geo, inputwatch, keyreaders, opshealth, osquery, patches, pixel
from . import posture, privacyseal, restarts, selfguard, spyware, storage
from . import toolchain, updates, winblocks, wslguard, wslmanifest
from . import agent_guardian
from .agent_guardian import AgentSample, window, time_span_seconds, audit, sample as agent_guardian_sample

# Re-export the functions the caller (jobs.py) links against.
audit = agent_guardian.audit
sample = agent_guardian_sample

__all__ = [
    "accelerator", "audiowatch", "bootchain", "bootintegrity", "canary",
    "containers", "content", "controlwatch", "dotnet_posture", "firmwareaudit",
    "fridaydefender", "geo", "inputwatch", "keyreaders", "opshealth",
    "osquery", "patches", "pixel", "posture", "privacyseal", "restarts",
    "selfguard", "spyware", "storage", "toolchain", "updates", "winblocks",
    "wslguard", "wslmanifest", "agent_guardian", "AgentSample",
]
