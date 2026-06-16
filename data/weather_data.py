"""
weather_data.py — Weather Data Fetching via Open-Meteo API (no API key required),
HTTP Response Builder, and Hashing.

Fetches real-time weather data from Open-Meteo free API (https://open-meteo.com/).
Zero API key needed, zero external dependencies.

Usage:
    from data.weather_data import fetch_weather, build_http_response, compute_hash
"""

import json
import hashlib
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# --- City coordinates for Open-Meteo API ---
CITY_COORDS = {
    "Beijing": (39.9042, 116.4074),
    "Shanghai": (31.2304, 121.4737),
    "Guangzhou": (23.1291, 113.2644),
    "Shenzhen": (22.5431, 114.0579),
    "Hangzhou": (30.2741, 120.1551),
    "Chengdu": (30.5728, 104.0668),
    "Wuhan": (30.5928, 114.3055),
    "Nanjing": (32.0603, 118.7969),
    "Xi'an": (34.3416, 108.9398),
    "Chongqing": (29.4316, 106.9123),
    "Tokyo": (35.6762, 139.6503),
    "Seoul": (37.5665, 126.9780),
    "Singapore": (1.3521, 103.8198),
    "Sydney": (-33.8688, 151.2093),
    "London": (51.5074, -0.1278),
    "Paris": (48.8566, 2.3522),
    "New York": (40.7128, -74.0060),
    "Los Angeles": (34.0522, -118.2437),
    "Chicago": (41.8781, -87.6298),
    "San Francisco": (37.7749, -122.4194),
}

CITIES = list(CITY_COORDS.keys())

# Weather codes mapping (WMO Weather interpretation codes)
WEATHER_CODES = {
    0: "晴天 Clear sky",
    1: "大部晴朗 Mainly clear",
    2: "多云 Partly cloudy",
    3: "阴天 Overcast",
    45: "雾 Foggy",
    48: "雾凇 Depositing rime fog",
    51: "小毛毛雨 Light drizzle",
    53: "毛毛雨 Moderate drizzle",
    55: "大毛毛雨 Dense drizzle",
    56: "冻小毛毛雨 Light freezing drizzle",
    57: "冻毛毛雨 Dense freezing drizzle",
    61: "小雨 Slight rain",
    63: "中雨 Moderate rain",
    65: "大雨 Heavy rain",
    66: "冻小雨 Light freezing rain",
    67: "冻大雨 Heavy freezing rain",
    71: "小雪 Slight snow",
    73: "中雪 Moderate snow",
    75: "大雪 Heavy snow",
    77: "雪粒 Snow grains",
    80: "小阵雨 Slight rain showers",
    81: "中阵雨 Moderate rain showers",
    82: "大阵雨 Violent rain showers",
    85: "小阵雪 Slight snow showers",
    86: "大阵雪 Heavy snow showers",
    95: "雷暴 Thunderstorm",
    96: "雷暴伴小冰雹 Thunderstorm with slight hail",
    99: "雷暴伴大冰雹 Thunderstorm with heavy hail",
}


def fetch_weather(city: str, api_key: str = "") -> bytes:
    """
    Fetch real-time weather data for a city from Open-Meteo API.
    No API key required — completely free.

    Parameters
    ----------
    city : str
        City name (e.g., "Beijing").
    api_key : str
        Ignored (kept for backward compatibility with existing API).

    Returns
    -------
    bytes
        Raw JSON response body with real weather data.
    """
    if city not in CITY_COORDS:
        # Default to Beijing if city not found
        lat, lon = CITY_COORDS.get("Beijing", (39.9042, 116.4074))
    else:
        lat, lon = CITY_COORDS[city]

    url = (
        f"https://api.open-meteo.com/v1/forecast?"
        f"latitude={lat}&longitude={lon}"
        f"&current=temperature_2m,relative_humidity_2m,apparent_temperature,"
        f"weather_code,wind_speed_10m,wind_direction_10m,surface_pressure"
        f"&timezone=auto"
    )

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "InfoSafety/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            data = json.loads(raw)
            normalized = _normalize_weather(data, city)
            return json.dumps(normalized, ensure_ascii=False, indent=2).encode("utf-8")
    except Exception as e:
        raise ConnectionError(f"Failed to fetch weather data from Open-Meteo: {e}")


def _normalize_weather(data: dict, city_name: str) -> dict:
    """Normalize Open-Meteo API response to our standard structure."""
    current = data.get("current", {})
    current_units = data.get("current_units", {})

    weather_code = current.get("weather_code", 0)
    description = WEATHER_CODES.get(weather_code, "未知 Unknown")

    return {
        "source": "open-meteo",
        "city": city_name,
        "country": data.get("timezone", ""),
        "temperature_c": current.get("temperature_2m", 0),
        "humidity_pct": current.get("relative_humidity_2m", 0),
        "pressure_hpa": current.get("surface_pressure", 0),
        "description": description,
        "wind_speed_ms": current.get("wind_speed_10m", 0),
        "wind_deg": current.get("wind_direction_10m", 0),
        "feels_like_c": current.get("apparent_temperature", 0),
        "observation_time": current.get("time", ""),
        "timestamp_utc": int(datetime.now(timezone.utc).timestamp()),
    }


def build_http_response(json_data: bytes, status_code: int = 200,
                        status_text: str = "OK",
                        source: str = "open-meteo") -> bytes:
    """
    Build a valid HTTP/1.1 response containing the JSON data as body.

    Parameters
    ----------
    json_data : bytes
        The JSON body (weather data).
    status_code : int
        HTTP status code.
    status_text : str
        HTTP status text.
    source : str
        Data source label for response header.

    Returns
    -------
    bytes
        Complete HTTP response including headers and body.
    """
    body_str = json_data.decode("utf-8") if isinstance(json_data, bytes) else json_data
    body_bytes = body_str.encode("utf-8")

    headers = (
        f"HTTP/1.1 {status_code} {status_text}\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Server: InfoSafety-Weather/1.0\r\n"
        f"X-Weather-Source: {source}\r\n"
        f"\r\n"
    )

    return headers.encode("utf-8") + body_bytes


def compute_hash(data: bytes) -> dict:
    """
    Compute MD5 and SHA-256 hashes of data.

    Parameters
    ----------
    data : bytes
        Input data.

    Returns
    -------
    dict
        {"md5": hex_str, "sha256": hex_str}
    """
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
