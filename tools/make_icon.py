"""Generate assets/icon.{png,ico}, icon_64.png (shield, check mark and settings sliders). Requires Pillow."""
from pathlib import Path
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "assets"
OUT.mkdir(exist_ok=True)
S = 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((0, 0, S - 1, S - 1), radius=220, fill=(18, 38, 63, 255))
cx = S // 2
d.polygon([(cx, 120), (850, 240), (850, 560), (cx, 910), (174, 560), (174, 240)], fill=(238, 244, 252, 255))
d.polygon([(cx, 200), (780, 290), (780, 545), (cx, 820), (244, 545), (244, 290)], fill=(24, 118, 210, 255))
# three settings sliders
for y, knob in ((350, 420), (470, 600), (590, 500)):
    d.rounded_rectangle((330, y, 694, y + 26), radius=13, fill=(255, 255, 255, 200))
    d.ellipse((knob - 36, y - 24, knob + 36, y + 50), fill=(255, 255, 255, 255))
# check mark badge
d.ellipse((560, 640, 840, 920), fill=(34, 168, 99, 255))
d.line([(620, 785), (690, 850), (790, 725)], fill=(255, 255, 255, 255), width=40, joint="curve")
img.resize((256, 256), Image.LANCZOS).save(OUT / "icon.png")
img.resize((64, 64), Image.LANCZOS).save(OUT / "icon_64.png")
img.save(OUT / "icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icons written to", OUT)
