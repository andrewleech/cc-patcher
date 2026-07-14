"""Anchor search for failed-patch diagnostics."""

from .context import DiscoveryContext


def anchor_search(
    ctx: DiscoveryContext, anchor: bytes,
    max_hits: int = 4, ctx_bytes: int = 120,
) -> list[str]:
    results: list[str] = []
    start = 0
    while True:
        idx = ctx.buf.find(anchor, start)
        if idx == -1:
            break
        in_payload = (
            ctx.bun.payload_start <= idx < ctx.bun.offsets_struct_offset
        )
        location = "payload" if in_payload else "outside-payload"
        lo = max(0, idx - ctx_bytes)
        hi = min(len(ctx.buf), idx + len(anchor) + ctx_bytes)
        snippet = ctx.buf[lo:hi]
        clean = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
        results.append(f"    offset 0x{idx:x} ({location}): ...{clean}...")
        start = idx + 1
        if len(results) >= max_hits:
            break
    return results
