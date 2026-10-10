"""Offline ``systemd-analyze security`` reimplementation."""

from __future__ import annotations

import pytest

from startup_sbom.initsys.systemd.hardening import (
    ALL_CAPS,
    CHECKS,
    SecurityInput,
    address_families,
    assess,
    capability_set,
    from_settings,
    namespaces_allowed,
    syscall_filter,
)
from startup_sbom.initsys.systemd.loader import Settings
from startup_sbom.initsys.systemd.parser import parse_unit_text


def view(text: str) -> Settings:
    return Settings(parse_unit_text(text))


def test_table_shape() -> None:
    assert len(CHECKS) == 81
    assert sum(c[1] for c in CHECKS) == 56_460
    assert len({c[0] for c in CHECKS}) == 81


def test_research_test_vector_unhardened_root() -> None:
    a = assess(SecurityInput())
    applicable = [c for c in a.checks if c.badness is not None]
    assert sum(c.weight for c in applicable) == 56_160  # SupplementaryGroups, RemoveIPC N/A
    assert sum(c.contribution for c in applicable) == 53_510
    assert (a.exposure, a.rating) == (9.6, "UNSAFE")
    umask = next(c for c in a.checks if c.id == "UMask=")
    assert umask.contribution == 50


def test_from_empty_service_matches_vector() -> None:
    s = from_settings(view("[Service]\nExecStart=/bin/true\n").section("Service"))
    assert assess(s).exposure == 9.6


@pytest.mark.parametrize(
    ("unit", "expected"),
    [
        ("[Service]\nUser=nobody\n", "nobody"),
        ("[Service]\nUser=www-data\n", "www-data"),
    ],
)
def test_user_lowers_score(unit: str, expected: str) -> None:
    s = from_settings(view(unit).section("Service"))
    assert s.user == expected
    assert assess(s).exposure < 9.6


def test_labels_and_extremes() -> None:
    worst = SecurityInput(
        notify_access="all",
        delegate=True,
        keyring_mode="shared",
        umask=0o000,
        ambient_capabilities=frozenset({"CAP_SYS_ADMIN"}),
    )
    a = assess(worst)
    assert (a.exposure, a.rating) == (10.0, "DANGEROUS")


def test_system_service_filter_expectations() -> None:
    s = from_settings(view("[Service]\nSystemCallFilter=@system-service\n").section("Service"))
    by = {c.id: c.badness for c in assess(s).checks}
    assert by["SystemCallFilter=~@resources"] == 9
    assert by["SystemCallFilter=~@privileged"] == 9
    for g in ("@swap", "@obsolete", "@clock", "@cpu-emulation", "@debug", "@mount", "@module",
              "@raw-io", "@reboot"):  # fmt: skip
        assert by[f"SystemCallFilter=~{g}"] == 0, g
    s2 = from_settings(
        view(
            "[Service]\nSystemCallFilter=@system-service\n"
            "SystemCallFilter=~@privileged @resources\n"
        ).section("Service")
    )
    by2 = {c.id: c.badness for c in assess(s2).checks}
    assert all(v == 0 for k, v in by2.items() if k.startswith("SystemCallFilter"))


def test_deny_list_filter() -> None:
    mode, calls = syscall_filter(["~@mount @swap"])
    assert mode == "deny"
    assert "mount" in calls
    assert "swapon" in calls
    s = SecurityInput(sc_mode=mode, sc_set=calls)
    by = {c.id: c.badness for c in assess(s).checks}
    assert by["SystemCallFilter=~@mount"] == 0
    assert by["SystemCallFilter=~@debug"] == 10


def test_capability_set_semantics() -> None:
    assert capability_set([]) == frozenset(ALL_CAPS)
    assert capability_set([""]) == frozenset()  # empty assignment: empty set
    assert capability_set(["CAP_NET_BIND_SERVICE"]) == {"CAP_NET_BIND_SERVICE"}
    assert capability_set(["CAP_A", "CAP_B"]) == {"CAP_A", "CAP_B"}
    drop = capability_set(["~CAP_SYS_ADMIN CAP_SYS_PTRACE"])
    assert "CAP_SYS_ADMIN" not in drop
    assert "CAP_CHOWN" in drop
    assert capability_set(["~CAP_SYS_ADMIN", "~CAP_CHOWN"]) == frozenset(ALL_CAPS) - {
        "CAP_SYS_ADMIN", "CAP_CHOWN",
    }  # fmt: skip
    assert capability_set([], ambient=True) == frozenset()
    assert capability_set(["net_bind_service"], ambient=True) == {"CAP_NET_BIND_SERVICE"}


def test_namespaces_and_families() -> None:
    assert namespaces_allowed(["yes"]) == frozenset()
    assert namespaces_allowed(["no"]) == namespaces_allowed([])
    assert namespaces_allowed(["net ipc"]) == {"net", "ipc"}
    assert "user" not in namespaces_allowed(["~user"])
    assert address_families(["AF_UNIX AF_INET"]) == ("allow", frozenset({"AF_UNIX", "AF_INET"}))
    assert address_families(["~AF_PACKET", "~AF_NETLINK"]) == (
        "deny", frozenset({"AF_PACKET", "AF_NETLINK"}),
    )  # fmt: skip
    assert address_families(["AF_UNIX", ""]) == (None, frozenset())
    assert address_families(["none"]) == ("allow", frozenset())


def test_derivations_dynamic_user_and_private_devices() -> None:
    s = from_settings(
        view("[Service]\nDynamicUser=yes\nPrivateDevices=yes\n").section("Service"),
        unit_prefix="svc",
    )
    assert s.user == "svc"
    assert not s.privileged
    assert s.protect_system == "strict"
    assert s.protect_home == "read-only"
    assert s.no_new_privileges
    assert s.restrict_suid_sgid
    assert s.remove_ipc
    assert s.private_tmp == "disconnected"
    assert s.private_mounts
    assert "CAP_MKNOD" not in s.capability_bounding_set
    assert s.device_policy == "closed"


def test_ip_address_deny_levels() -> None:
    def score(deny: str, allow: str = "") -> int | None:
        text = f"[Service]\nIPAddressDeny={deny}\n" + (f"IPAddressAllow={allow}\n" if allow else "")
        s = from_settings(view(text).section("Service"))
        return next(c.badness for c in assess(s).checks if c.id == "IPAddressDeny=")

    assert score("10.0.0.0/8") == 10
    assert score("any") == 0
    assert score("any", "localhost") == 2
    assert score("any", "192.168.0.0/16") == 5
