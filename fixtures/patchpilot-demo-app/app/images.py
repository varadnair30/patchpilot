from io import BytesIO

from PIL import Image


def make_thumbnail(data: bytes, size: tuple[int, int] = (128, 128)) -> bytes:
    img = Image.open(BytesIO(data))
    img.thumbnail(size)
    out = BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()
