#!/usr/bin/env python3
"""Rasterize the sbx mark to the PNG the notification sink embeds.

    ./assets/render-logo.py 128 assets/sbx.png

A desktop notification daemon is a separate process: it opens the icon file itself, and
most of them decode it through gdk-pixbuf, which needs librsvg present before it will
touch an SVG at all. Raster is the portable floor, so the mark ships as a PNG even though
its source of truth is the SVG this script reads.

The geometry is parsed out of `docs-site/static/assets/logo.svg` rather than restated
here, so the two cannot drift: edit the SVG and re-run this. That parsing is deliberately
narrow -- it understands the shape of *that* file (axis-aligned rects, one rounded rect
masked out, one fill colour) and nothing else. A structural change to the SVG should make
this fail loudly rather than emit a mark that is quietly wrong.

Pure stdlib on purpose. The alternative is a build-time dependency on a rendering library
for one 500-byte asset that changes about never.
"""

import re
import struct
import sys
import zlib
from pathlib import Path

SVG = Path(__file__).resolve().parents[1] / "docs-site" / "static" / "assets" / "logo.svg"

# Samples per pixel per axis. The mark is a handful of straight edges plus four small
# arcs, so 4x4 coverage sampling antialiases them well below the point of visibility at
# any size a notification daemon renders.
SS = 4


def parse(svg):
    """The mark as (fill, viewbox size, solid rects, [gate]) read out of the SVG."""
    side = float(re.search(r'viewBox="0 0 (\d+) \1"', svg).group(1))
    fill = re.search(r'<g fill="(#[0-9A-Fa-f]{6})"', svg).group(1)
    rgb = tuple(int(fill[i : i + 2], 16) for i in (1, 3, 5))

    solid, gate = [], None
    for tag in re.findall(r"<rect[^>]*>", svg):
        attr = dict(re.findall(r'(\w+)="([^"]*)"', tag))
        box = tuple(float(attr.get(k, 0)) for k in ("x", "y", "width", "height"))
        if attr.get("fill") == "#ffffff":
            continue  # The mask's opaque base: keeps everything the gate does not cut.
        if attr.get("fill") == "#000000":
            gate = (*box, float(attr.get("rx", 0)))
        else:
            solid.append(box)

    if not solid or gate is None:
        raise SystemExit(f"{SVG}: expected solid rects and one masked-out gate")
    return rgb, side, solid, gate


def covered(x, y, solid, gate):
    """Is the point (x, y), in SVG user units, part of the mark?"""
    if not any(rx <= x < rx + rw and ry <= y < ry + rh for rx, ry, rw, rh in solid):
        return False
    gx, gy, gw, gh, r = gate
    if not (gx <= x < gx + gw and gy <= y < gy + gh):
        return True
    # Inside the gate's bounding box, only the rounded corners stay part of the mark:
    # clamp to the corner-arc centre and keep what falls outside the radius.
    cx = min(max(x, gx + r), gx + gw - r)
    cy = min(max(y, gy + r), gy + gh - r)
    return (x - cx) ** 2 + (y - cy) ** 2 > r * r


def render(size, rgb, side, solid, gate):
    """`size` rows of RGBA, the fill colour throughout with coverage as alpha."""
    scale = side / (size * SS)
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            hits = sum(
                covered(
                    (px * SS + sx + 0.5) * scale,
                    (py * SS + sy + 0.5) * scale,
                    solid,
                    gate,
                )
                for sy in range(SS)
                for sx in range(SS)
            )
            row += bytes((*rgb, round(255 * hits / (SS * SS))))
        rows.append(bytes(row))
    return rows


def write_png(rows, size, path):
    """8-bit RGBA, no interlacing -- the plainest PNG every decoder handles."""

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    # One filter byte (0 = None) per scanline. Filtering would buy nothing on flat colour.
    raw = b"".join(b"\x00" + row for row in rows)
    Path(path).write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def main():
    if not 3 <= len(sys.argv) <= 4:
        raise SystemExit(f"usage: {sys.argv[0]} <size> <out.png> [logo.svg]")
    size, out = int(sys.argv[1]), sys.argv[2]
    # The light-mode mark by default; the dark-mode twin is the same geometry in a lighter
    # fill, so it renders through the same path by naming it here.
    svg = Path(sys.argv[3]) if len(sys.argv) == 4 else SVG
    rgb, side, solid, gate = parse(svg.read_text())
    write_png(render(size, rgb, side, solid, gate), size, out)
    print(f"{out}: {size}x{size} from {svg.name}")


if __name__ == "__main__":
    main()
