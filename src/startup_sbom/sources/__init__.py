"""Target parsing and acquisition: turn a target string into a read-only RootFS.

``parse_target("docker:nginx")`` validates a target without side effects;
``open_target(...)`` acquires it (directory, live host, tarball, docker-archive,
OCI layout, or a live engine container/image) and returns an
:class:`AcquiredTarget` whose ``close()`` removes every temporary file.
Container metadata travels out-of-band in :class:`ContainerInfo`; nothing is
ever written into, extracted from, or executed out of the analysed tree.
"""

from startup_sbom.sources.oci import Platform
from startup_sbom.sources.targets import (
    SCHEMES,
    AcquiredTarget,
    TargetSpec,
    open_target,
    parse_target,
    validate_spec,
)

__all__ = [
    "SCHEMES",
    "AcquiredTarget",
    "Platform",
    "TargetSpec",
    "open_target",
    "parse_target",
    "validate_spec",
]
