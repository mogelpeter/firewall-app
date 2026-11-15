"""Generates assets/icon.ico, icon.png and icon.rgba (64x64 raw RGBA for the window icon). Needs Pillow."""
from PIL import Image, ImageDraw

S = 1024


def draw():
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((0, 0, S - 1, S - 1), radius=S // 5, fill=(10, 7, 18, 255))
    # shield
    cx, top, bot, w = S // 2, int(S * 0.15), int(S * 0.88), int(S * 0.62)
    l, r, mid = cx - w // 2, cx + w // 2, int(S * 0.52)
    pts = [(l, top + 60), (cx, top), (r, top + 60), (r, mid), (cx + w // 4, int(S * 0.76)), (cx, bot),
           (cx - w // 4, int(S * 0.76)), (l, mid)]
    d.polygon(pts, fill=(139, 92, 246, 255))
    # "blocked" bar
    d.line([(cx - w // 4, int(S * 0.62)), (cx + w // 4, int(S * 0.34))], fill=(255, 255, 255, 255), width=int(S * 0.09))
    d.ellipse((cx - w // 4 - 8, int(S * 0.62) - 8, cx - w // 4 + 8, int(S * 0.62) + 8), fill=(255, 255, 255, 255))
    return im


big = draw()
sizes = [16, 24, 32, 48, 64, 128, 256]
big.resize((256, 256), Image.LANCZOS).save("assets/icon.ico", sizes=[(s, s) for s in sizes])
big.resize((192, 192), Image.LANCZOS).save("assets/icon.png")
open("assets/icon.rgba", "wb").write(big.resize((64, 64), Image.LANCZOS).tobytes())
