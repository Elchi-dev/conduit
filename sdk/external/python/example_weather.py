#!/usr/bin/env python3
"""Example: current weather from Open-Meteo (no API key needed).

Install: copy this file and conduit_module.py into <data>/modules/, make this
file executable (chmod +x), restart Conduit, and add a Weather connection.
"""
import json
import urllib.parse
import urllib.request

from conduit_module import ActionError, Module, run


class Weather(Module):
    manifest = {
        "id": "weather",
        "name": "Weather",
        "version": "0.1.0",
        "description": "Current conditions for a place, from Open-Meteo.",
        "category": "Example",
        "configSchema": {
            "type": "object",
            "required": ["latitude", "longitude"],
            "properties": {
                "place": {"type": "string", "description": "A name to show"},
                "latitude": {"type": "number"},
                "longitude": {"type": "number"},
            },
        },
        "actions": [{"name": "now", "title": "Current weather", "risk": "read"}],
    }

    def __init__(self):
        self.places = {}

    def configure(self, host, instance, config):
        if "latitude" not in config or "longitude" not in config:
            raise ActionError("set a latitude and a longitude")
        self.places[instance] = config

    def invoke(self, instance, action, input, dry_run):
        if action != "now":
            raise ActionError("unknown action " + action)
        c = self.places.get(instance)
        if not c:
            raise ActionError("this instance isn't set up")
        q = urllib.parse.urlencode({"latitude": c["latitude"], "longitude": c["longitude"], "current": "temperature_2m,wind_speed_10m"})
        with urllib.request.urlopen("https://api.open-meteo.com/v1/forecast?" + q, timeout=15) as r:
            cur = json.load(r)["current"]
        return {"output": {"place": c.get("place", ""), "temperature": cur["temperature_2m"], "wind": cur["wind_speed_10m"]}}

    def health(self, instance):
        return {"status": "ok" if instance in self.places else "unconfigured"}


if __name__ == "__main__":
    run(Weather())
