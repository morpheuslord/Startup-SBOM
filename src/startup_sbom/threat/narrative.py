"""Plain-English narratives for threats and attack chains (templates from research §8).

Pure string assembly over already-computed facts; no analysis happens here.
"""

from __future__ import annotations

from startup_sbom.models import AttackChain, Consequence, Reachability, Threat
from startup_sbom.threat.reachability import describe_listen

_CONSEQUENCE_PHRASE = {
    Consequence.RCE: "execute arbitrary code",
    Consequence.PRIVESC: "escalate privileges",
    Consequence.AUTH_BYPASS: "bypass authentication",
    Consequence.INFO_DISCLOSURE: "disclose sensitive information",
    Consequence.TAMPERING: "tamper with data or files",
    Consequence.DOS: "cause a denial of service",
    Consequence.SUPPLY_CHAIN: "run attacker-supplied code planted in the supply chain",
    Consequence.OTHER: "affect the system",
}
_PRECONDITION_PHRASE = {
    "remote": "An unauthenticated remote attacker",
    "adjacent": "An attacker on the local network",
    "physical": "An attacker with physical access",
    "local": "A local unprivileged attacker",
}


def precondition_actor(precondition: str) -> str:
    """Human description of the attacker required by a precondition."""
    if precondition.startswith("local:"):
        return f"A local attacker running as {precondition.split(':', 1)[1]}"
    return _PRECONDITION_PHRASE.get(precondition, f"An attacker ({precondition})")


def postcondition_phrase(postcondition: str, run_as: str | None) -> str:
    """Human description of the state the attacker reaches."""
    if postcondition == "root":
        return "code execution as root"
    if postcondition == "container_escape":
        return "escape from the container to the host"
    if postcondition.startswith("local:"):
        return f"code execution as {postcondition.split(':', 1)[1]}"
    if postcondition == "remote":
        return "a remotely reachable foothold"
    return postcondition


def reach_clause(threat: Threat) -> str:
    """How the attacker reaches the vulnerable code."""
    if threat.listens:
        where = ", ".join(describe_listen(li) for li in threat.listens[:3])
        return f"reach {where}"
    reach = {
        Reachability.NETWORK_SERVICE: "reach the exposed service",
        Reachability.BOOT_SERVICE: "influence a service started at boot",
        Reachability.LINKED_BY_SERVICE: "reach a service that loads the vulnerable library",
        Reachability.ON_DEMAND_SERVICE: "trigger the socket/timer-activated service",
        Reachability.SETUID: "invoke the setuid/privileged binary",
        Reachability.KERNEL: "run code on the host kernel",
        Reachability.INSTALLED: "reach the installed component",
    }
    return reach.get(threat.reachability, "reach the component")


def threat_narrative(
    threat: Threat,
    *,
    package_label: str,
    service_label: str | None,
    binary: str | None,
    epss: float | None,
    kev: bool,
    techniques: str,
) -> str:
    """CTID three-step statement enriched with this system's context."""
    actor = precondition_actor(threat.precondition)
    outcome = postcondition_phrase(threat.postcondition, threat.run_as)
    cons = (
        ", ".join(_CONSEQUENCE_PHRASE[c] for c in _ordered(threat.consequences))
        or "affect the system"
    )
    ctx = [package_label]
    if service_label:
        where = f"owner of {service_label}"
        if threat.run_as:
            where += f", runs as {threat.run_as}"
        if binary:
            where += f", executable {binary}"
        ctx.append(where)
    elif binary:
        ctx.append(binary)
    where_clause = " (" + "; ".join(ctx[1:]) + ")" if len(ctx) > 1 else ""

    epss_s = f"EPSS {epss:.3f}" if epss is not None else "EPSS unknown"
    kev_s = "listed in CISA KEV" if kev else "not in CISA KEV"
    ssvc_s = f" SSVC decision: {threat.ssvc.decision.value}." if threat.ssvc else ""
    tech_s = f" ATT&CK: {techniques}." if techniques else ""
    mit = ""
    if threat.mitigations:
        mit = " In-place hardening that weakens this: " + ", ".join(threat.mitigations[:4]) + "."

    return (
        f"{actor} who can {reach_clause(threat)} could exploit {threat.vulnerability} in "
        f"{package_label}{where_clause} to {cons}, gaining {outcome}. "
        f"{kev_s}; {epss_s}.{tech_s}{ssvc_s}{mit} "
        f"Remediation: {threat.remediation}."
    )


def chain_narrative(chain: AttackChain, step_lines: list[str]) -> str:
    """Step-by-step chain story ending with the overall verdict."""
    head = (
        f"{precondition_actor(chain.entry)} can reach "
        f"{postcondition_phrase(chain.goal, None)} in {len(chain.steps)} "
        f"step{'s' if len(chain.steps) != 1 else ''}:"
    )
    tail = (
        f"Overall: {chain.entry} → {chain.goal}; "
        f"score {chain.score:.0f}/100; SSVC {chain.ssvc_decision.value}"
        + (" (all steps mitigated by hardening)" if chain.mitigated else "")
        + "."
    )
    return " ".join([head, *step_lines, tail])


def step_line(
    index: int,
    tactic: str | None,
    technique_id: str | None,
    title: str,
    from_state: str,
    to_state: str,
    mitigated_by: list[str],
) -> str:
    """One numbered chain step."""
    tag = f"{tactic}, {technique_id}" if tactic and technique_id else (tactic or technique_id or "")
    tag = f" ({tag})" if tag else ""
    text = f"Step {index}{tag}: {title} [{from_state} → {to_state}]."
    if mitigated_by:
        text += " Mitigated by " + ", ".join(mitigated_by[:3]) + "."
    return text


def _ordered(consequences: list[Consequence]) -> list[Consequence]:
    order = [
        Consequence.RCE,
        Consequence.SUPPLY_CHAIN,
        Consequence.PRIVESC,
        Consequence.AUTH_BYPASS,
        Consequence.TAMPERING,
        Consequence.INFO_DISCLOSURE,
        Consequence.DOS,
        Consequence.OTHER,
    ]
    return [c for c in order if c in consequences]
