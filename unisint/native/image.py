"""Image metadata: EXIF via Pillow (GPS, camera, timestamps) plus reverse
image-search links. Operates on a locally uploaded file path."""
from __future__ import annotations


from ..base import MODE_SELF, Context, Module, register
from ..models import EntityType


def _to_deg(value, ref) -> float | None:
    try:
        d, m, s = value
        dec = float(d) + float(m) / 60 + float(s) / 3600
        if ref in ("S", "W"):
            dec = -dec
        return round(dec, 6)
    except Exception:
        return None


@register
class ExifImage(Module):
    name = "exif"
    label = "Image EXIF"
    category = "image"
    accepts = {EntityType.IMAGE}
    modes = {MODE_SELF}
    weight = 1

    async def run(self, ctx: Context) -> None:
        path = ctx.entity.meta.get("path")
        if not path:
            return
        try:
            from PIL import ExifTags, Image
        except Exception:
            ctx.log("Pillow not available", level="warn")
            return
        try:
            img = Image.open(path)
            exif = img._getexif() or {}
        except Exception as exc:
            ctx.log(f"cannot read image: {exc}", level="warn")
            return
        if not exif:
            ctx.log("no EXIF metadata present", level="muted")
        tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
        for key in ("Make", "Model", "DateTimeOriginal", "Software"):
            if tags.get(key):
                ctx.finding(f"{key}: {tags[key]}", source=self.name)
        gps = tags.get("GPSInfo")
        if gps:
            g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps.items()}
            lat = _to_deg(g.get("GPSLatitude"), g.get("GPSLatitudeRef"))
            lon = _to_deg(g.get("GPSLongitude"), g.get("GPSLongitudeRef"))
            if lat is not None and lon is not None:
                ctx.add_entity(
                    EntityType.LOCATION, f"{lat},{lon}", source=self.name,
                    rel="photo_location",
                    meta={"lat": lat, "lon": lon,
                          "map": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"})

        # Reverse image search links (manual; no auto-upload).
        links = [
            {"name": "Google Lens", "url": "https://lens.google.com/"},
            {"name": "Yandex", "url": "https://yandex.com/images/"},
            {"name": "TinEye", "url": "https://tineye.com/"},
            {"name": "Bing", "url": "https://www.bing.com/visualsearch"},
        ]
        ctx.finding("reverse image search (upload manually)",
                    source=self.name, meta={"links": links})
