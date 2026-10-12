"""Threat reversal and attack-chain mapping.

* :func:`reverse_vulnerabilities` — place each vulnerability in the scanned
  system's context (reachability, pre/post-conditions, consequences, ATT&CK,
  STRIDE, SSVC, a transparent risk score, a narrative and remediation).
* :func:`build_attack_chains` — chain threats and misconfigurations into ranked
  ``remote → root → container-escape/persistence`` attack paths.
* :func:`technique` — look up a MITRE ATT&CK technique by id.

All runtime analysis is offline: it consults only the report and the package
data files under :mod:`startup_sbom.data`.
"""

from __future__ import annotations

from startup_sbom.threat.attack import technique
from startup_sbom.threat.chains import build_attack_chains
from startup_sbom.threat.reverse import reverse_vulnerabilities

__all__ = ["build_attack_chains", "reverse_vulnerabilities", "technique"]
