from __future__ import annotations

import ipaddress
import socket

from models import TargetSpec
from errors import TargetError


def _add_target(out: list[TargetSpec], seen: set[str], value: str, address: str, family: str, max_targets: int) -> None:
    key = f"{family}:{address}"
    if key in seen:
        return
    if len(out) >= max_targets:
        raise TargetError(f"target expansion exceeds max-targets={max_targets}")
    out.append(TargetSpec(value, address, family, address))
    seen.add(key)


def expand_targets(values: list[str], max_targets: int = 256) -> list[TargetSpec]:
    raw: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                raw.append(part)

    out: list[TargetSpec] = []
    seen: set[str] = set()
    for item in raw:
        try:
            net = ipaddress.ip_network(item, strict=False)
            addresses = list(net.hosts())
            if net.num_addresses == 1:
                addresses = [net.network_address]
            for address in addresses:
                family = "IPv6" if address.version == 6 else "IPv4"
                _add_target(out, seen, item, str(address), family, max_targets)
            continue
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(item, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise TargetError(f"cannot resolve target '{item}': {exc}") from exc

        for family, *_rest, sockaddr in infos:
            address = sockaddr[0]
            family_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
            _add_target(out, seen, item, address, family_name, max_targets)

    if not out:
        raise TargetError("no targets supplied")
    return out
