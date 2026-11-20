#!/usr/bin/env python3
"""report_pdf.py: turn a verified vibe-check report (.md) into a branded PDF you can send.

    python3 report_pdf.py .vibe-check/reports/2026-11-14.md     -> .vibe-check/reports/2026-11-14.pdf

Python 3.8+, standard library only. Runs on this computer; nothing is sent anywhere.
It refuses to write a PDF when the report contains a secret (the same check coverage.py uses),
and the cover numbers come from .vibe-check/results.json, written by coverage.py, never typed.
"""
import importlib.util
import json
import re
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
W, H = 595.28, 841.89                     # A4
ML, MR, MT, MB = 48, 48, 66, 50           # margins (top leaves room for the brand band)
CW = W - ML - MR
TAGLINE = "Find what breaks before your users do"
SUBLINE = "Security, privacy and launch audit for web and mobile apps"
FIRST_TOP = 136                           # page 1 has the tall band with the full logo

# ---- brand ----
INK = (0.043, 0.043, 0.047)               # #0b0b0c, the banner background
GREEN = (0.133, 0.773, 0.369)             # #22c55e
TEXT = (0.11, 0.11, 0.13)
MUTED = (0.42, 0.43, 0.47)
RULE = (0.86, 0.87, 0.89)
SOFT = (0.955, 0.958, 0.965)
COLORS = {"green": GREEN, "red": (0.86, 0.15, 0.15), "amber": (0.92, 0.58, 0.05), "blue": (0.15, 0.45, 0.92),
          "grey": (0.62, 0.63, 0.66), "purple": (0.55, 0.3, 0.85)}
STATUS = {"✅": "green", "✔": "green", "✓": "green", "🟢": "green", "❌": "red", "🔴": "red", "❗": "red",
          "⚠": "amber", "🟡": "amber", "❓": "blue", "🔵": "blue", "➖": "grey", "🔧": "purple"}
SWAP = {"→": "->", "←": "<-", "↔": "<->", "⇒": "=>", "≥": ">=", "≤": "<=", "≠": "!=", "≈": "~", "₹": "Rs ", "✗": "x",
        " ": " ", " ": " ", " ": " ", "↩": "", "⬆": "^", "−": "-", "‑": "-"}

# The vibe-check logo: the dot-matrix wordmark from assets/banner.svg ('#' = lit dot, '.' = unlit dot).
LOGO = """#...#.#####.####..#####........###..#...#.#####..###..#...#
#...#...#...#...#.#...........#...#.#...#.#.....#...#.#..#.
#...#...#...#...#.#...........#.....#...#.#.....#.....#.#..
#...#...#...####..####..#####.#.....#####.####..#.....##...
#...#...#...#...#.#...........#.....#...#.#.....#.....#.#..
.#.#....#...#...#.#...........#...#.#...#.#.....#...#.#..#.
..#...#####.####..#####........###..#...#.#####..###..#...#""".splitlines()


def circle(cx, cy, r):
    """A filled circle as four Bezier curves (every PDF viewer draws these)."""
    k = 0.5523 * r
    return ("%.2f %.2f m %.2f %.2f %.2f %.2f %.2f %.2f c %.2f %.2f %.2f %.2f %.2f %.2f c "
            "%.2f %.2f %.2f %.2f %.2f %.2f c %.2f %.2f %.2f %.2f %.2f %.2f c f" % (
                cx + r, cy, cx + r, cy + k, cx + k, cy + r, cx, cy + r, cx - k, cy + r, cx - r, cy + k, cx - r, cy,
                cx - r, cy - k, cx - k, cy - r, cx, cy - r, cx + k, cy - r, cx + r, cy - k, cx + r, cy))


def logo_ops(x, top, pitch, unlit=(0.2, 0.2, 0.215), lit=(0.914, 0.914, 0.918)):
    """The dot-matrix logo: unlit dots first, lit dots on top."""
    out = []
    for colour, char, radius in ((unlit, ".", 0.2), (lit, "#", 0.34)):
        out.append("%.3f %.3f %.3f rg" % colour)
        for r, row in enumerate(LOGO):
            for c, ch in enumerate(row):
                if ch == char:
                    out.append(circle(x + c * pitch, top - r * pitch, pitch * radius))
    return "\n".join(out)


# Adobe font metrics (1/1000 em) for the characters we draw; anything else uses 556.
_HR = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
      [278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
       667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556,
       278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334,
       260, 334, 584]
_HB = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
      [333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
       667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556,
       333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389,
       280, 389, 584]
EXTRA = {"·": 278, "—": 1000, "–": 556, "…": 1000, "•": 350, "’": 222, "‘": 222, "“": 333, "”": 333, "×": 584, "é": 556}
FONTS = {"R": ("F1", "Helvetica", _HR), "B": ("F2", "Helvetica-Bold", _HB), "I": ("F3", "Helvetica-Oblique", _HR),
         "C": ("F4", "Courier", None)}


def width(s, font, size):
    _, _, table = FONTS[font]
    if table is None:
        return len(s) * 600 * size / 1000
    total = 0
    for ch in s:
        o = ord(ch)
        total += table[o - 32] if 32 <= o < 127 else EXTRA.get(ch, 556)
    return total * size / 1000


def pdf_str(s):
    out = []
    for b in s.encode("cp1252", "replace"):
        c = chr(b)
        if c in "\\()":
            out.append("\\" + c)
        elif 32 <= b < 127:
            out.append(c)
        else:
            out.append("\\%03o" % b)
    return "(" + "".join(out) + ")"


# ---- inline text: **bold**, *italic*, `code`, [links](url), status symbols as coloured dots, bars ----
def clean(s):
    s = re.sub(r"<!--.*?-->", "", s)
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = s.replace("️", "").replace("‍", "")
    return "".join(SWAP.get(ch, ch) for ch in s)


def segments(s, base="R"):
    """-> list of (kind, value, font): kind is 'text', 'dot' (colour name) or 'bar' (0..1)."""
    s = clean(s)
    out = []
    for part in re.split(r"(`[^`]+`|\*\*[^*]+\*\*|(?<!\*)\*[^*\s](?:[^*]|\*\*[^*]+\*\*)*?\*(?!\*))", s):
        if not part:
            continue
        if part.startswith("*") and not part.startswith("**") and part.endswith("*") and "**" in part and len(part) > 2:
            out.extend(segments(part[1:-1], "B" if base == "B" else "I"))   # italic with bold inside
            continue
        if part.startswith("`") and part.endswith("`") and len(part) > 1:
            inner, font = part[1:-1], "C"
        elif part.startswith("**") and part.endswith("**") and len(part) > 3:
            inner, font = part[2:-2], "B"
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            inner, font = part[1:-1], ("B" if base == "B" else "I")
        else:
            inner, font = part, base
        for piece in re.split(r"([█░]+)", inner):
            if not piece:
                continue
            if set(piece) <= {"█", "░"}:
                out.append(("bar", piece.count("█") / len(piece), font))
                continue
            buf = ""
            for ch in piece:
                if ch in STATUS:
                    if buf:
                        out.append(("text", buf, font)); buf = ""
                    out.append(("dot", STATUS[ch], font))
                elif ord(ch) < 256 or ch in EXTRA:
                    buf += ch
                elif ord(ch) >= 0x2000:          # other emoji and pictographs: leave out
                    continue
                else:
                    buf += "?"
            if buf:
                out.append(("text", buf, font))
    return out


def seg_width(seg, size):
    kind, val, font = seg
    if kind == "dot":
        return size * 0.95
    if kind == "bar":
        return size * 5.2
    return width(val, font, size)


def wrap(segs, maxw, size):
    """Split into lines that fit maxw. Words never split unless one word is wider than the line."""
    tokens = []
    for kind, val, font in segs:
        if kind != "text":
            tokens.append((kind, val, font)); continue
        for w in re.split(r"(\s+)", val):
            if w:
                tokens.append(("text", " " if w.isspace() else w, font))
    lines, cur, cw = [], [], 0.0
    for t in tokens:
        tw = seg_width(t, size)
        if t[0] == "text" and t[1] == " ":
            if cur:
                cur.append(t); cw += tw
            continue
        if cw + tw > maxw and cur:
            while cur and cur[-1][1] == " ":
                cw -= seg_width(cur.pop(), size)
            lines.append(cur); cur, cw = [], 0.0
        if tw > maxw and t[0] == "text":             # one very long word or path: break it
            piece = ""
            for ch in t[1]:
                if width(piece + ch, t[2], size) > maxw and piece:
                    lines.append([("text", piece, t[2])]); piece = ""
                piece += ch
            cur, cw = [("text", piece, t[2])], width(piece, t[2], size)
            continue
        cur.append(t); cw += tw
    while cur and cur[-1][1] == " ":
        cur.pop()
    if cur:
        lines.append(cur)
    return lines or [[]]


# ---- page layout ----
class Doc:
    def __init__(self, project, version, date):
        self.pages, self.ops = [], None
        self.project, self.version, self.date = project, version, date
        self.new_page()

    def new_page(self):
        self.ops = []
        self.pages.append(self.ops)
        self.y = H - (FIRST_TOP if len(self.pages) == 1 else MT)

    def ensure(self, h):
        if self.y - h < MB:
            self.new_page()

    def color(self, rgb, stroke=False):
        self.ops.append("%.3f %.3f %.3f %s" % (rgb + ("RG" if stroke else "rg",)))

    def rect(self, x, y, w, h, rgb):
        self.color(rgb); self.ops.append("%.2f %.2f %.2f %.2f re f" % (x, y, w, h))

    def line(self, x1, y1, x2, y2, rgb=RULE, lw=0.6):
        self.color(rgb, True); self.ops.append("%.2f w %.2f %.2f m %.2f %.2f l S" % (lw, x1, y1, x2, y2))

    def text(self, x, y, s, font="R", size=10, rgb=TEXT):
        if not s:
            return
        self.color(rgb)
        self.ops.append("BT /%s %.1f Tf %.2f %.2f Td %s Tj ET" % (FONTS[font][0], size, x, y, pdf_str(s)))

    def dot(self, x, y, size, colour):
        r = size * 0.33
        cx, cy = x + size * 0.42, y + size * 0.33
        k = 0.5523 * r
        self.color(COLORS[colour])
        self.ops.append("%.2f %.2f m %.2f %.2f %.2f %.2f %.2f %.2f c %.2f %.2f %.2f %.2f %.2f %.2f c "
                        "%.2f %.2f %.2f %.2f %.2f %.2f c %.2f %.2f %.2f %.2f %.2f %.2f c f" % (
                            cx + r, cy, cx + r, cy + k, cx + k, cy + r, cx, cy + r, cx - k, cy + r, cx - r, cy + k, cx - r, cy,
                            cx - r, cy - k, cx - k, cy - r, cx, cy - r, cx + k, cy - r, cx + r, cy - k, cx + r, cy))

    def draw_line(self, x, y, segs, size, rgb=TEXT):
        for seg in segs:
            kind, val, font = seg
            if kind == "dot":
                self.dot(x, y, size, val)
            elif kind == "bar":
                bw = size * 4.6
                self.rect(x, y, bw, size * 0.62, RULE)
                if val > 0:
                    self.rect(x, y, bw * val, size * 0.62, GREEN if val >= 0.75 else COLORS["amber"] if val >= 0.6 else COLORS["red"])
            else:
                self.text(x, y, val, font, size, rgb)
            x += seg_width(seg, size)

    def para(self, segs, size=9.6, indent=0, rgb=TEXT, gap=4, lead=1.42):
        lines = wrap(segs, CW - indent, size)
        for ln in lines:
            self.ensure(size * lead)
            self.y -= size * lead
            self.draw_line(ML + indent, self.y + size * 0.25, ln, size, rgb)
        self.y -= gap

    # ---- blocks ----
    def heading(self, s, level):
        size = {1: 17, 2: 13.5, 3: 11}.get(level, 10.5)
        segs = segments(s, "B")
        self.ensure(size * 2.6 + 30)               # keep a heading with what follows it
        self.y -= size * (0.9 if level > 2 else 1.2)
        if level == 2:
            self.rect(ML, self.y - size * 1.05, 3, size * 1.25, GREEN)
            indent = 10
        else:
            indent = 0
        for ln in wrap(segs, CW - indent, size):
            self.y -= size * 1.25
            self.draw_line(ML + indent, self.y + size * 0.2, ln, size)
        if level == 1:
            self.line(ML, self.y - 6, W - MR, self.y - 6, RULE, 0.8)
            self.y -= 8
        self.y -= 5

    def bullet(self, s, depth, marker):
        size = 9.6
        indent = 12 + depth * 14
        segs = segments(s)
        lines = wrap(segs, CW - indent - 4, size)
        for i, ln in enumerate(lines):
            self.ensure(size * 1.42)
            self.y -= size * 1.42
            if i == 0:
                if marker == "box":
                    self.color(MUTED, True)
                    self.ops.append("0.7 w %.2f %.2f %.2f %.2f re S" % (ML + indent - 12, self.y + 1.2, 7, 7))
                elif marker == "•":
                    self.dot(ML + indent - 13, self.y + 1.5, 7, "grey")
                else:
                    self.text(ML + indent - 14, self.y + 2.4, marker, "R", size, MUTED)
            self.draw_line(ML + indent, self.y + size * 0.25, ln, size)
        self.y -= 2

    def quote(self, s):
        size = 9.4
        lines = wrap(segments(s, "I"), CW - 22, size)
        top = None
        for ln in lines:
            self.ensure(size * 1.45)
            if top is None or self.y > top:
                top = self.y
            self.y -= size * 1.45
            self.rect(ML + 2, self.y - 2, 2.2, size * 1.45, GREEN)
            self.draw_line(ML + 14, self.y + size * 0.25, ln, size, (0.25, 0.26, 0.3))
        self.y -= 5

    def code(self, lines_in):
        size = 8.2
        per = int((CW - 16) / (size * 0.6))
        lines = []
        for raw in lines_in:
            raw = clean(raw).expandtabs(4)
            raw = "".join(ch for ch in raw if ord(ch) < 256 or ch in EXTRA)
            while len(raw) > per:
                lines.append(raw[:per]); raw = raw[per:]
            lines.append(raw)
        i = 0
        while i < len(lines):
            room = max(1, int((self.y - MB - 10) / (size * 1.35)))
            if room < 2 and i == 0:
                self.new_page(); continue
            chunk = lines[i:i + room]
            h = len(chunk) * size * 1.35 + 10
            self.rect(ML, self.y - h, CW, h, SOFT)
            yy = self.y - 5
            for ln in chunk:
                yy -= size * 1.35
                self.text(ML + 8, yy + 2, ln, "C", size, (0.2, 0.22, 0.27))
            self.y -= h + 6
            i += len(chunk)
            if i < len(lines):
                self.new_page()

    def table(self, rows):
        size = 8.4
        pad = 4
        ncol = max(len(r) for r in rows)
        rows = [r + [""] * (ncol - len(r)) for r in rows]
        cells = [[segments(c, "B" if ri == 0 else "R") for c in r] for ri, r in enumerate(rows)]
        natural = [max(sum(seg_width(s, size) for s in cells[ri][ci]) for ri in range(len(rows))) + 2 * pad for ci in range(ncol)]
        total = sum(natural)
        if total <= CW:
            widths = [n * CW / total for n in natural] if total > CW * 0.7 else natural
        else:
            floor = [min(n, 46) for n in natural]
            rest = CW - sum(floor)
            extra = [n - f for n, f in zip(natural, floor)]
            se = sum(extra) or 1
            widths = [f + rest * e / se for f, e in zip(floor, extra)]
        tw = sum(widths)

        def row_lines(ri):
            return [wrap(cells[ri][ci], widths[ci] - 2 * pad, size) for ci in range(ncol)]

        def draw_row(ri, header=False):
            ls = row_lines(ri)
            h = max(len(x) for x in ls) * size * 1.3 + 2 * pad - 1
            if self.y - h < MB:
                self.new_page()
                if not header:
                    draw_row(0, True)
            if header:
                self.rect(ML, self.y - h, tw, h, SOFT)
            x = ML
            for ci in range(ncol):
                yy = self.y - pad
                for ln in ls[ci]:
                    yy -= size * 1.3
                    self.draw_line(x + pad, yy + size * 0.28, ln, size, TEXT)
                x += widths[ci]
            self.y -= h
            self.line(ML, self.y, ML + tw, self.y, RULE, 0.5)

        def row_h(ri):
            return max(len(x) for x in row_lines(ri)) * size * 1.3 + 2 * pad - 1
        self.ensure(row_h(0) + (row_h(1) if len(rows) > 1 else 0) + 4)   # never leave a header alone at the bottom
        self.line(ML, self.y, ML + tw, self.y, RULE, 0.5)
        draw_row(0, True)
        for ri in range(1, len(rows)):
            draw_row(ri)
        self.y -= 8

    # ---- cover summary from results.json ----
    def cover(self, res):
        verdict = res.get("verdict", "")
        col = COLORS["red"] if "DO NOT" in verdict else COLORS["amber"] if "AFTER" in verdict else GREEN
        t = res.get("totals", {})
        h = 104
        self.ensure(h + 10)
        top = self.y
        self.rect(ML, top - h, CW, h, SOFT)
        self.rect(ML, top - h, 5, h, col)
        score = str(res.get("score", "?"))
        self.text(ML + 22, top - 62, score, "B", 46, col)
        sx = ML + 22 + width(score, "B", 46) + 4
        self.text(sx, top - 62, "/100", "B", 14, MUTED)
        word = re.sub(r"^[^A-Za-z]+", "", clean(verdict)).strip()
        self.text(ML + 22, top - 84, res.get("band", ""), "R", 10, MUTED)
        x2 = ML + 175
        self.dot(x2, top - 34, 16, "red" if "DO NOT" in verdict else "amber" if "AFTER" in verdict else "green")
        self.text(x2 + 20, top - 33, word, "B", 15, TEXT)
        if res.get("capped"):
            self.text(x2, top - 52, "Score capped at 69 while a blocker is open", "I", 8.6, MUTED)
        stats = [("green", "%s passed" % t.get("passed", 0)), ("red", "%s must fix" % t.get("blockers", 0)),
                 ("amber", "%s should fix" % t.get("should_fix", 0)), ("blue", "%s need your answer" % t.get("need_answer", 0))]
        xx = x2
        for colour, label in stats:
            self.dot(xx, top - 74, 9, colour)
            self.text(xx + 10, top - 73, label, "R", 9, TEXT)
            xx += 12 + width(label, "R", 9) + 12
        self.text(x2, top - 91, "%s of %s checks that apply were checked · %s don't apply to this app" % (
            t.get("checked", "?"), t.get("apply", "?"), t.get("dont_apply", "?")), "R", 8.4, MUTED)
        self.y = top - h - 14


def brand(doc, ops, n, total):
    """The band at the top and the footer on every page."""
    pre = []
    def c(rgb):
        pre.append("%.3f %.3f %.3f rg" % rgb)
    if n == 1:      # the cover band, like the README banner
        bh = 120
        c(INK); pre.append("0 %.2f %.2f %d re f" % (H - bh, W, bh))
        c(GREEN); pre.append("0 %.2f %.2f 2.5 re f" % (H - bh - 2.5, W))
        pitch = 5.2
        lx = (W - 58 * pitch) / 2
        pre.append(logo_ops(lx, H - 24, pitch))
        sub = TAGLINE.upper()
        size, track = 8.6, 2.6
        sw = len(sub) * 600 * size / 1000 + track * (len(sub) - 1)
        pre.append("BT /F4 %.1f Tf %.2f Tc %.2f %.2f Td 0.900 0.900 0.910 rg %s Tj ET 0 Tc" % (size, track, (W - sw) / 2, H - 76, pdf_str(sub)))
        sw2 = width(SUBLINE, "R", 9)
        pre.append("BT /F1 9 Tf %.2f %.2f Td 0.631 0.631 0.667 rg %s Tj ET" % ((W - sw2) / 2, H - 91, pdf_str(SUBLINE)))
        tag = (doc.project + " · " if doc.project else "") + (doc.date or "")
        if tag:
            tw_ = width(tag, "R", 8)
            c(GREEN); pre.append(circle((W - tw_) / 2 - 8, H - 107.4, 2.5))
            pre.append("BT /F1 8 Tf %.2f %.2f Td 0.443 0.443 0.478 rg %s Tj ET" % ((W - tw_) / 2, H - 110, pdf_str(tag)))
    else:           # a slim band with the small logo
        c(INK); pre.append("0 %.2f %.2f 40 re f" % (H - 40, W))
        c(GREEN); pre.append("0 %.2f %.2f 2 re f" % (H - 42, W))
        pre.append(logo_ops(ML, H - 10.5, 2.75))
        right = "Pre-launch audit" + (" · " + doc.project if doc.project else "")
        pre.append("BT /F1 8.5 Tf %.2f %.2f Td 0.62 0.63 0.66 rg %s Tj ET" % (W - MR - width(right, "R", 8.5), H - 24.5, pdf_str(right)))
    left = "vibe-check v%s · %s · made on your computer, nothing was sent anywhere" % (doc.version, doc.date)
    pg = "Page %d of %d" % (n, total)
    pre.append("%.3f %.3f %.3f RG 0.5 w %.2f 34 m %.2f 34 l S" % (RULE + (ML, W - MR)))
    pre.append("BT /F1 7.6 Tf %.2f 22 Td 0.42 0.43 0.47 rg %s Tj ET" % (ML, pdf_str(left)))
    pre.append("BT /F1 7.6 Tf %.2f 22 Td 0.42 0.43 0.47 rg %s Tj ET" % (W - MR - width(pg, "R", 7.6), pdf_str(pg)))
    return "\n".join(pre + ops)


def render(md, res, project, version, date):
    doc = Doc(project, version, date)
    lines = md.splitlines()
    i, covered = 0, False
    para = []

    def flush():
        if para:
            doc.para(segments(" ".join(x.strip() for x in para)))
            para.clear()

    in_comment = False
    while i < len(lines):
        raw = lines[i]
        s = raw.strip()
        if in_comment:
            in_comment = "-->" not in s
            i += 1; continue
        if s.startswith("<!--"):
            flush()
            in_comment = "-->" not in s
            i += 1; continue
        if s.startswith("```") or s.startswith("~~~"):
            flush()
            fence = s[:3]
            block = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith(fence):
                block.append(lines[i]); i += 1
            doc.code(block or [""])
            i += 1; continue
        if not s:
            flush(); i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            flush()
            level = len(m.group(1))
            doc.heading(m.group(2), level)
            if level == 1 and res and not covered:
                doc.cover(res); covered = True
            i += 1; continue
        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", s):
            flush(); doc.ensure(12); doc.y -= 6; doc.line(ML, doc.y, W - MR, doc.y); doc.y -= 8
            i += 1; continue
        if s.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.match(r"^:?-{2,}:?$", c) for c in cells if c):
                    rows.append(cells)
                i += 1
            if rows:
                doc.table(rows)
            continue
        if s.startswith(">"):
            flush()
            q = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                q.append(lines[i].strip().lstrip(">").strip()); i += 1
            doc.quote(" ".join(x for x in q if x))
            continue
        m = re.match(r"^(\s*)([-*+]|\d+[.)])\s+(\[[ xX]\]\s+)?(.*)$", raw)
        if m:
            flush()
            depth = len(m.group(1).expandtabs(4)) // 2
            marker = "box" if m.group(3) else ("•" if m.group(2) in "-*+" else m.group(2))
            text = m.group(4)
            i += 1
            while i < len(lines) and lines[i].strip() and not re.match(r"^\s*([-*+]|\d+[.)])\s+|^\s*[|>#`]", lines[i]) \
                    and lines[i].startswith(" "):
                text += " " + lines[i].strip(); i += 1
            doc.bullet(text, min(depth, 3), marker)
            continue
        para.append(s)
        i += 1
    flush()
    return doc


def build_pdf(doc):
    objs = []
    def add(b):
        objs.append(b if isinstance(b, bytes) else b.encode("latin-1")); return len(objs)
    fonts = {}
    for key, (name, base, _) in FONTS.items():
        fonts[name] = add("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>" % base)
    pages_id = len(objs) + 1
    add("")                                   # placeholder for /Pages
    kids = []
    total = len(doc.pages)
    font_res = " ".join("/%s %d 0 R" % (n, i) for n, i in fonts.items())
    for n, ops in enumerate(doc.pages, 1):
        data = zlib.compress(brand(doc, ops, n, total).encode("latin-1"))
        cid = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
        kids.append(add("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << %s >> >> /Contents %d 0 R >>"
                        % (pages_id, W, H, font_res, cid)))
    objs[pages_id - 1] = ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join("%d 0 R" % k for k in kids), total)).encode()
    info = add("<< /Title %s /Producer (vibe-check report_pdf.py) /Creator (vibe-check) >>" % pdf_str(
        "vibe-check report" + (": " + doc.project if doc.project else "")))
    cat = add("<< /Type /Catalog /Pages %d 0 R >>" % pages_id)
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, b in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + b + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offsets:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, cat, info, xref)
    return bytes(out)


def find_secrets(path):
    spec = importlib.util.spec_from_file_location("vc_coverage", HERE / "coverage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return list(mod.find_secrets(path))


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip()); return 0 if argv else 2
    src = Path(argv[0])
    if not src.exists():
        print(f"No report at {src}"); return 1
    hits = find_secrets(src)
    if hits:
        for line_no, kind, _ in hits[:5]:
            print(f"SECRET: {src}:{line_no} looks like a {kind}. Mask it (first 4 characters only) before making a PDF.")
        print("NO PDF: the report contains a secret."); return 1
    md = src.read_text("utf-8")
    vc = next((p for p in [src.parent, *src.parents] if p.name == ".vibe-check"), src.parent)
    res = {}
    rj = vc / "results.json"
    if rj.exists():
        try:
            res = json.loads(rj.read_text("utf-8"))
        except ValueError:
            res = {}
    project = vc.resolve().parent.name if vc.name == ".vibe-check" else ""
    m = re.search(r"^#\s+vibe-check report:\s*(.+)$", md, re.M)
    if m:
        project = clean(m.group(1)).strip()
    version = res.get("vibe_check_version") or "?"
    date = res.get("date") or ""
    out = src.with_suffix(".pdf")
    doc = render(md, res, project, version, date)
    out.write_bytes(build_pdf(doc))
    print(f"PDF: {out.resolve()} ({len(doc.pages)} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
