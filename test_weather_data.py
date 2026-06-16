"""
test_weather_data.py — Unit tests for weather data module

Tests:
  - Real weather fetch returns valid JSON structure
  - Hash computation is deterministic
  - HTTP response builder produces valid HTTP format
  - City list is populated
"""

import sys
import os
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.weather_data import (
    fetch_weather,
    build_http_response,
    compute_hash,
    CITIES,
    _normalize_weather,
)


class TestWeatherData(unittest.TestCase):
    """Tests for weather data fetching and processing."""

    # ------------------------------------------------------------------
    # Weather fetch (real data from Open-Meteo)
    # ------------------------------------------------------------------

    def test_01_fetch_returns_valid_json(self):
        """fetch_weather returns valid JSON with required fields."""
        raw = fetch_weather("Beijing")
        data = json.loads(raw)
        self.assertIn("city", data)
        self.assertEqual(data["city"], "Beijing")
        self.assertIn("temperature_c", data)
        self.assertIn("humidity_pct", data)
        self.assertIn("pressure_hpa", data)
        self.assertIn("description", data)
        self.assertIn("source", data)
        self.assertEqual(data["source"], "open-meteo")
        self.assertIn("observation_time", data)

    def test_02_fetch_returns_bytes(self):
        """fetch_weather returns bytes, not str."""
        raw = fetch_weather("Tokyo")
        self.assertIsInstance(raw, bytes)

    def test_03_fetch_different_cities(self):
        """Different cities return different data."""
        raw1 = fetch_weather("London")
        raw2 = fetch_weather("Tokyo")
        data1 = json.loads(raw1)
        data2 = json.loads(raw2)
        self.assertEqual(data1["source"], "open-meteo")
        self.assertEqual(data2["source"], "open-meteo")
        self.assertEqual(data1["city"], "London")
        self.assertEqual(data2["city"], "Tokyo")

    def test_04_fetch_handles_unknown_city(self):
        """fetch_weather with unknown city defaults to Beijing gracefully."""
        raw = fetch_weather("NonexistentCity")
        data = json.loads(raw)
        self.assertIn("city", data)

    # ------------------------------------------------------------------
    # HTTP response builder
    # ------------------------------------------------------------------

    def test_05_build_http_response_valid_format(self):
        """HTTP response builder produces valid HTTP/1.1 response."""
        json_data = b'{"city": "Beijing"}'
        resp = build_http_response(json_data)
        text = resp.decode("utf-8")
        self.assertTrue(text.startswith("HTTP/1.1 200 OK"))
        self.assertIn("Content-Type: application/json", text)
        self.assertIn("Content-Length:", text)
        self.assertIn('{"city": "Beijing"}', text)

    def test_06_build_http_response_custom_status(self):
        """HTTP response supports custom status code."""
        json_data = b'{"error": "not found"}'
        resp = build_http_response(json_data, status_code=404, status_text="Not Found")
        text = resp.decode("utf-8")
        self.assertIn("404 Not Found", text)

    def test_07_build_http_response_content_length_correct(self):
        """Content-Length header matches actual body size."""
        json_bytes = b'{"key": "value"}'
        resp = build_http_response(json_bytes)
        parts = resp.split(b"\r\n\r\n", 1)
        headers = parts[0].decode("utf-8")
        body = parts[1]
        self.assertIn(f"Content-Length: {len(body)}", headers)

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    def test_08_compute_hash_deterministic(self):
        """Hash computation is deterministic for same input."""
        data = b"test weather data"
        h1 = compute_hash(data)
        h2 = compute_hash(data)
        self.assertEqual(h1["md5"], h2["md5"])
        self.assertEqual(h1["sha256"], h2["sha256"])

    def test_09_compute_hash_different_for_different_data(self):
        """Different data produces different hashes."""
        h1 = compute_hash(b"hello")
        h2 = compute_hash(b"world")
        self.assertNotEqual(h1["md5"], h2["md5"])
        self.assertNotEqual(h1["sha256"], h2["sha256"])

    def test_10_compute_hash_returns_both_md5_and_sha256(self):
        """Hash result contains both md5 and sha256 keys."""
        result = compute_hash(b"data")
        self.assertIn("md5", result)
        self.assertIn("sha256", result)
        self.assertEqual(len(result["md5"]), 32)   # MD5 = 16 bytes = 32 hex chars
        self.assertEqual(len(result["sha256"]), 64)  # SHA-256 = 32 bytes = 64 hex chars

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def test_11_normalize_weather_structure(self):
        """_normalize_weather produces expected fields from Open-Meteo response."""
        om_data = {
            "current": {
                "temperature_2m": 25.5,
                "relative_humidity_2m": 60,
                "apparent_temperature": 27.0,
                "weather_code": 0,
                "wind_speed_10m": 3.5,
                "wind_direction_10m": 180,
                "surface_pressure": 1013.0,
                "time": "2026-06-16T15:00",
            },
            "current_units": {},
            "timezone": "Asia/Shanghai",
        }
        normalized = _normalize_weather(om_data, "Beijing")
        self.assertEqual(normalized["city"], "Beijing")
        self.assertEqual(normalized["country"], "Asia/Shanghai")
        self.assertEqual(normalized["temperature_c"], 25.5)
        self.assertEqual(normalized["humidity_pct"], 60)
        self.assertEqual(normalized["pressure_hpa"], 1013.0)
        self.assertEqual(normalized["description"], "晴天 Clear sky")
        self.assertEqual(normalized["wind_speed_ms"], 3.5)
        self.assertEqual(normalized["source"], "open-meteo")
        self.assertEqual(normalized["observation_time"], "2026-06-16T15:00")

    # ------------------------------------------------------------------
    # City list
    # ------------------------------------------------------------------

    def test_12_cities_list_populated(self):
        """CITIES list contains multiple cities."""
        self.assertGreater(len(CITIES), 10)
        self.assertIn("Beijing", CITIES)
        self.assertIn("Tokyo", CITIES)
        self.assertIn("London", CITIES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
