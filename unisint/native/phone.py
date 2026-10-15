"""Phone parsing via the `phonenumbers` library: validity, country,
carrier, timezones. Pure-offline, no network."""
from __future__ import annotations

from ..base import MODE_SELF, Context, Module, register
from ..models import EntityType


@register
class PhoneInfo(Module):
    name = "phone_info"
    label = "Phone Metadata"
    category = "phone"
    accepts = {EntityType.PHONE}
    modes = {MODE_SELF}
    weight = 1

    async def run(self, ctx: Context) -> None:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone

        raw = ctx.entity.value
        try:
            num = phonenumbers.parse(raw, None)
        except phonenumbers.NumberParseException:
            # Try assuming it already has a country code with '+'
            ctx.log("could not parse phone (needs +country code)", level="warn")
            return
        valid = phonenumbers.is_valid_number(num)
        region = geocoder.description_for_number(num, "en")
        carr = carrier.name_for_number(num, "en")
        zones = timezone.time_zones_for_number(num)
        ctx.finding(
            f"valid={valid} region={region or '?'} carrier={carr or '?'}",
            source=self.name, basis="derived",
            meta={
                "valid": valid,
                "region": region,
                "carrier": carr,
                "timezones": list(zones),
                "e164": phonenumbers.format_number(
                    num, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(
                    num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            },
        )
        if region:
            ctx.add_entity(EntityType.LOCATION, region, source=self.name,
                           rel="phone_region",
                           basis="derived")
