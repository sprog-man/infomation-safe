.PHONY: test e2e demo check exit clean web web-test check-web

PYTHON := python
TESTS := test_sensor.py test_aes.py test_rsa.py test_hmac.py test_client.py test_server.py test_end_to_end.py

# Install dependencies (none required — stdlib only)
setup:
	@echo "No external dependencies. Python 3.6+ required."
	@$(PYTHON) --version
	@$(PYTHON) init_check.py

# Run all unit tests
test:
	@echo "Running all test scripts..."
	@for t in $(TESTS); do \
		echo ""; \
		echo "==> $$t"; \
		$(PYTHON) $$t || { echo "FAILED: $$t"; exit 1; }; \
	done
	@echo ""; \
	echo "All tests passed."

# Run end-to-end pipeline
e2e:
	@echo "Running end-to-end pipeline..."
	@$(PYTHON) main.py --e2e

# Run standalone demo (no server)
demo:
	@echo "Running standalone demo..."
	@$(PYTHON) main.py --demo

# Session exit checklist (5 dimensions)
exit:
	@echo "Running session exit checklist..."
	@$(PYTHON) exit_check.py

# Full verification: test + e2e + init_check
check: test e2e
	@echo ""; \
	echo "=== Full verification complete ==="

# Clean up artifacts
clean:
	@echo "Cleaning up..."
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@find . -type f -name '*.pyo' -delete 2>/dev/null || true
	@rm -rf .coverage htmlcov 2>/dev/null || true
	@echo "Done."

# Start web frontend (http://localhost:8080)
web:
	@echo "Starting web frontend on http://127.0.0.1:8080..."
	@$(PYTHON) server_api.py

# Run web API tests
web-test:
	@echo "Running web API tests..."
	@$(PYTHON) test_server_api.py

# Full verification: test + e2e + web-test
check-web: check web-test
	@echo ""; \
	echo "=== Full verification (including web) complete ==="
