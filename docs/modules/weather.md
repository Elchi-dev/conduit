# Weather

Current weather, rain in the next hours, the week's highs and lows and,
optionally, air quality for your places, from [Open-Meteo](https://open-meteo.com).
It needs no account or key, and every action is read-only.

**Setup.** Add your `places`, each with a `name`, `latitude` and `longitude`
(up to 10; the first is the default). Choose `units`: `metric` (°C, km/h,
mm, the default) or `imperial` (°F, mph, inches). Turn on `airQuality` to
also offer air quality. For a [self-hosted Open-Meteo](https://github.com/open-meteo/open-meteo),
set `url` (and `airQualityUrl`) to its address; otherwise the public API is
used (free for non-commercial use).

| Action | Risk | Notes |
| --- | --- | --- |
| `places` | read | The names of the places in settings, the first marked as the default. Never their coordinates: they're where people live and work, and outputs go to the audit log. |
| `today` | read | A line per place: temperature and conditions now, today's low and high, and the chance and amount of rain in the next 12 hours. The daily brief uses it. |
| `current` | read | Temperature, feels-like, conditions, humidity, wind speed and direction and precipitation now. |
| `precipitation` | read | Hour by hour for the next 12 `hours` (up to 48): chance of precipitation, amount, temperature and conditions. |
| `forecast` | read | Day by day for the next 7 `days` (up to 16): high, low, conditions, precipitation amount and chance, sunrise and sunset. |
| `air_quality` | read | European and US AQI (with the European band, good to extremely poor), PM10, PM2.5, ozone and nitrogen dioxide now. Only when `airQuality` is on. |

`current`, `precipitation`, `forecast` and `air_quality` take a `place` by
name (only one from settings; matching ignores case) or `latitude` and
`longitude` (checked to be in range), and use the first place when given
neither. Times are the place's local time.

**Daily brief.** When a weather instance is set up, the [daily brief](brief.md)
includes each place's `today` line.

**Security.** There are no credentials. Places and coordinates are checked
before they reach a request, and the client won't follow a redirect to
another host.
