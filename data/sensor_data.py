"""
sensor_data.py - Sensor Data Simulation & Collection

Generates simulated sensor readings (temperature, humidity, pressure)
as structured JSON strings for network transmission.

All data is synthetic -- no external services required.
"""

import json
import time
import random
from datetime import datetime, timezone


# --- Sensor ID pool ---
SENSOR_IDS = [
    "SENSOR-TEMP-001",
    "SENSOR-HUM-001",
    "SENSOR-PRES-001",
    "SENSOR-TEMP-002",
    "SENSOR-HUM-002",
    "SENSOR-PRES-002",
]


def generate_reading(sensor_id: str) -> dict:
    """
    Generate a single sensor reading.

    Returns a dict with:
      - sensor_id: the sensor identifier
      - timestamp: ISO-8601 UTC timestamp
      - readings: a dict of sensor_type -> value

    Temperature:  15.0 ~ 35.0 C
    Humidity:     30.0 ~ 80.0 %
    Pressure:     990.0 ~ 1030.0 hPa
    """
    ts = datetime.now(timezone.utc).isoformat()

    if "TEMP" in sensor_id:
        value = round(random.uniform(15.0, 35.0), 2)
        sensor_type = "temperature"
    elif "HUM" in sensor_id:
        value = round(random.uniform(30.0, 80.0), 2)
        sensor_type = "humidity"
    elif "PRES" in sensor_id:
        value = round(random.uniform(990.0, 1030.0), 2)
        sensor_type = "pressure"
    else:
        raise ValueError(f"Unknown sensor type in id: {sensor_id}")

    return {
        "sensor_id": sensor_id,
        "timestamp": ts,
        "readings": {
            sensor_type: value,
        },
    }


def generate_batch(count: int = 5) -> str:
    """
    Generate a batch of sensor readings and return as a JSON string.

    Parameters
    ----------
    count : int
        Number of readings to generate (1-100).

    Returns
    -------
    str
        JSON string containing a structured payload with:
          - batch_id: a unique identifier
          - generated_at: ISO timestamp
          - readings: list of individual reading dicts
    """
    if not (1 <= count <= 100):
        raise ValueError("count must be between 1 and 100")

    readings = []
    for _ in range(count):
        sid = random.choice(SENSOR_IDS)
        readings.append(generate_reading(sid))

    payload = {
        "batch_id": f"BATCH-{int(time.time())}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reading_count": count,
        "readings": readings,
    }

    return json.dumps(payload, indent=2, ensure_ascii=False)


def generate_single() -> str:
    """
    Generate a single sensor reading and return as a JSON string.

    Returns
    -------
    str
        JSON string of a single reading dict.
    """
    return json.dumps(generate_reading(random.choice(SENSOR_IDS)), indent=2, ensure_ascii=False)


if __name__ == "__main__":
    # Quick demo
    print("=== Single Reading ===")
    print(generate_single())
    print()
    print("=== Batch (5 readings) ===")
    print(generate_batch(5))
