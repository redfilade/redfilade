"""Build the flat (2D) Redfilade brand assets. Run: python3 assets/brand/build.py

The mascot banner, social preview and avatar PNGs come from compose/build.sh instead.

Needs fontTools, rsvg-convert and Inter Display installed.

The wordmark is outlined from Inter Display (SIL OFL 1.1), so the SVGs
render identically everywhere without depending on installed fonts.
"""
import os
import subprocess

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

OUT = os.path.dirname(os.path.abspath(__file__))
os.makedirs(OUT, exist_ok=True)

RED = "#E5383B"
RED_DEEP = "#A8222A"
INK = "#10141C"
CREAM = "#F4EFE6"
MUTED = "#8A93A3"


def text_path(text, font_file, size, x, y, tracking=0.0):
    """Return (svg path d, advance width) for text set at baseline (x, y)."""
    font = TTFont(font_file)
    gs = font.getGlyphSet()
    cmap = font.getBestCmap()
    upm = font["head"].unitsPerEm
    scale = size / upm
    pen = SVGPathPen(gs)
    cursor = 0.0
    for ch in text:
        name = cmap[ord(ch)]
        glyph = gs[name]
        tp = TransformPen(pen, (scale, 0, 0, -scale, x + cursor, y))
        glyph.draw(tp)
        cursor += glyph.width * scale + tracking * size
    return pen.getCommands(), cursor - tracking * size


BOLD = "/usr/share/fonts/opentype/inter/InterDisplay-Bold.otf"
MEDIUM = "/usr/share/fonts/opentype/inter/InterDisplay-Medium.otf"


def mark(eye=RED, outline=None):
    """The sentinel mark, drawn on a 512 x 512 grid, no background."""
    ol = f' stroke="{outline}" stroke-width="6" stroke-linejoin="round"' if outline else ""
    return f"""
  <!-- antenna -->
  <path d="M256 122 V96" stroke="{outline or CREAM}" stroke-width="10" stroke-linecap="round"/>
  <circle cx="256" cy="84" r="13" fill="{RED}"/>
  <!-- head, in defilade behind the parapet -->
  <path d="M156 236 C156 164 200 118 256 118 C312 118 356 164 356 236 Z" fill="{CREAM}"{ol}/>
  <!-- visor -->
  <rect x="184" y="160" width="144" height="50" rx="25" fill="{INK}"/>
  <circle cx="226" cy="185" r="12" fill="{eye}"/>
  <circle cx="288" cy="185" r="14.5" fill="none" stroke="{eye}" stroke-width="4.5"/>
  <circle cx="288" cy="185" r="4" fill="{eye}"/>
  <path d="M288 164 V172 M288 198 V206 M267 185 H275 M301 185 H309" stroke="{eye}" stroke-width="4" stroke-linecap="round"/>
  <!-- shield with battlement top -->
  <path d="M104 206 H152 V228 H360 V206 H408 V302 C408 392 338 448 256 482 C174 448 104 392 104 302 Z" fill="{RED}"/>
  <path d="M104 206 H152 V228 H360 V206 H408 V266 H104 Z" fill="{RED_DEEP}"/>
  <path d="M190 228 V266 M256 228 V266 M322 228 V266 M128 246 H384" stroke="{RED}" stroke-width="5" opacity=".55"/>
  <!-- mitts gripping the wall -->
  <rect x="164" y="212" width="50" height="34" rx="15" fill="{CREAM}"{ol}/>
  <rect x="298" y="212" width="50" height="34" rx="15" fill="{CREAM}"{ol}/>
  <path d="M181 220 V236 M197 220 V236 M315 220 V236 M331 220 V236" stroke="{INK}" stroke-width="3.5" stroke-linecap="round" opacity=".35"/>
  <!-- terminal prompt -->
  <path d="M206 322 L240 350 L206 378" fill="none" stroke="{CREAM}" stroke-width="17" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M260 382 H306" stroke="{CREAM}" stroke-width="17" stroke-linecap="round"/>
"""


def svg(w, h, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" aria-labelledby="t"><title id="t">{title}</title>{body}</svg>\n')


def write(name, content):
    p = os.path.join(OUT, name)
    with open(p, "w") as f:
        f.write(content)
    return p


def png(svg_path, png_name, w, h=None):
    h = h or w
    subprocess.run(["rsvg-convert", "-w", str(w), "-h", str(h), "-o",
                    os.path.join(OUT, png_name), svg_path], check=True)


# 1. Bare mark (transparent)
p = write("redfilade-mark.svg", svg(512, 512, mark(), "Redfilade sentinel"))
png(p, "redfilade-mark-512.png", 512)

# 2. Avatar for the GitHub org (dark tile, mark slightly inset)
avatar = f'<rect width="512" height="512" fill="{INK}"/>' \
         f'<g transform="translate(36 30) scale(.86)">{mark()}</g>'
p = write("redfilade-avatar.svg", svg(512, 512, avatar, "Redfilade"))


# 3. Horizontal lockups, dark and light text variants
def lockup(text_color, outline=None):
    size = 150
    d_red, w_red = text_path("red", BOLD, size, 0, 0, tracking=-0.02)
    d_rest, w_rest = text_path("filade", BOLD, size, w_red - 0.02 * size, 0, tracking=-0.02)
    total = w_red + w_rest
    W, H = int(250 + 40 + total + 30), 260
    body = (f'<g transform="translate(0 -6) scale(.52)">{mark(outline=outline)}</g>'
            f'<g transform="translate(290 178)"><path d="{d_red}" fill="{RED}"/>'
            f'<path d="{d_rest}" fill="{text_color}"/></g>')
    return W, H, body


for variant, color, ol in (("dark", CREAM, None), ("light", INK, INK)):
    W, H, body = lockup(color, ol)
    p = write(f"redfilade-lockup-{variant}.svg", svg(W, H, body, "Redfilade"))
    png(p, f"redfilade-lockup-{variant}.png", W * 2, H * 2)

# 4. Social preview 1280 x 640
W, H = 1280, 640
size = 132
d_red, w_red = text_path("red", BOLD, size, 0, 0, tracking=-0.02)
d_rest, w_rest = text_path("filade", BOLD, size, w_red - 0.02 * size, 0, tracking=-0.02)
tag1, _ = text_path("The open MCP red-team range.", MEDIUM, 44, 0, 0)
tag2, _ = text_path("Break it here, so nobody breaks it out there.", MEDIUM, 32, 0, 0)
grid = "".join(f'<path d="M{x} 0 V{H}" />' for x in range(0, W + 1, 40)) + \
       "".join(f'<path d="M0 {y} H{W}" />' for y in range(0, H + 1, 40))
social = (f'<rect width="{W}" height="{H}" fill="{INK}"/>'
          f'<g stroke="{CREAM}" stroke-width="1" opacity=".045">{grid}</g>'
          f'<rect x="0" y="{H-10}" width="{W}" height="10" fill="{RED}"/>'
          f'<g transform="translate(70 92) scale(.86)">{mark()}</g>'
          f'<g transform="translate(560 300)"><path d="{d_red}" fill="{RED}"/><path d="{d_rest}" fill="{CREAM}"/></g>'
          f'<g transform="translate(564 380)"><path d="{tag1}" fill="{CREAM}"/></g>'
          f'<g transform="translate(564 440)"><path d="{tag2}" fill="{MUTED}"/></g>')
p = write("redfilade-social.svg", svg(W, H, social, "Redfilade, the open MCP red-team range"))

print(sorted(os.listdir(OUT)))
