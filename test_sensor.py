"""
test_sensor.py - Validate sensor data format and structure.

Run with: python test_sensor.py

Expects all assertions to pass (no output on success).
Prints summary on completion.
"""

import json
import unittest
from data.sensor_data import generate_reading, generate_batch, generate_single, SENSOR_IDS


class TestGenerateReading(unittest.TestCase):
    """Tests for single sensor reading generation."""

    def test_returns_valid_json(self):
        """generate_reading result should be a valid dict that serializes to JSON."""
        result = generate_reading("SENSOR-TEMP-001")
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        self.assertIsNotNone(parsed)

    def test_contains_required_fields(self):
        """Each reading must have sensor_id, timestamp, and readings."""
        result = generate_reading("SENSOR-TEMP-001")
        self.assertIn("sensor_id", result)
        self.assertIn("timestamp", result)
        self.assertIn("readings", result)

    def test_temperature_range(self):
        """Temperature values should be between 15.0 and 35.0 C."""
        for _ in range(100):
            r = generate_reading("SENSOR-TEMP-001")
            self.assertTrue(15.0 <= r["readings"]["temperature"] <= 35.0)

    def test_humidity_range(self):
        """Humidity values should be between 30.0 and 80.0 %."""
        for _ in range(100):
            r = generate_reading("SENSOR-HUM-001")
            self.assertTrue(30.0 <= r["readings"]["humidity"] <= 80.0)

    def test_pressure_range(self):
        """Pressure values should be between 990.0 and 1030.0 hPa."""
        for _ in range(100):
            r = generate_reading("SENSOR-PRES-001")
            self.assertTrue(990.0 <= r["readings"]["pressure"] <= 1030.0)

    def test_sensor_id_preserved(self):
        """The returned sensor_id must match the input."""
        for sid in SENSOR_IDS:
            r = generate_reading(sid)
            self.assertEqual(r["sensor_id"], sid)

    def test_timestamp_is_string(self):
        """Timestamp should be an ISO-8601 formatted string."""
        r = generate_reading("SENSOR-TEMP-001")
        self.assertIsInstance(r["timestamp"], str)
        self.assertIn("+", r["timestamp"])  # UTC offset

    def test_invalid_sensor_id(self):
        """Unknown sensor ID should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_reading("SENSOR-UNKNOWN-001")


class TestGenerateBatch(unittest.TestCase):
    """Tests for batch reading generation."""

    def test_default_count(self):
        """Default batch should produce 5 readings."""
        result = generate_batch()
        data = json.loads(result)
        self.assertEqual(data["reading_count"], 5)
        self.assertEqual(len(data["readings"]), 5)

    def test_custom_count(self):
        """Batch with explicit count should match."""
        for count in [1, 10, 50, 100]:
            data = json.loads(generate_batch(count))
            self.assertEqual(data["reading_count"], count)
            self.assertEqual(len(data["readings"]), count)

    def test_output_is_valid_json(self):
        """Output of generate_batch should be valid JSON."""
        json.loads(generate_batch(3))  # raises if invalid

    def test_contains_batch_metadata(self):
        """Batch payload should have batch_id, generated_at, reading_count."""
        data = json.loads(generate_batch(1))
        self.assertIn("batch_id", data)
        self.assertIn("generated_at", data)
        self.assertIn("reading_count", data)
        self.assertIn("readings", data)

    def test_out_of_range_count(self):
        """Count outside 1-100 should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_batch(0)
        with self.assertRaises(ValueError):
            generate_batch(101)


class TestGenerateSingle(unittest.TestCase):
    """Tests for single-reading JSON generation."""

    def test_returns_json_string(self):
        """generate_single should return a non-empty JSON string."""
        result = generate_single()
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_parses_correctly(self):
        """Parsed JSON should have sensor_id, timestamp, readings."""
        data = json.loads(generate_single())
        self.assertIn("sensor_id", data)
        self.assertIn("timestamp", data)
        self.assertIn("readings", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
