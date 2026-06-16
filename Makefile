.PHONY: test e2e demo check exit clean sender receiver done setup-hooks lint

PYTHON := python
TESTS := test_sensor.py test_aes.py test_rsa.py test_hmac.py test_client.py test_server.py test_end_to_end.py test_weather_data.py test_weather_pipeline.py test_pcap.py

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

# Full verification: lint + test + e2e
check: lint test e2e
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

# Start sender (http://localhost:8080) — C/S split architecture
# Note: Receiver must be started first (sender fetches RSA public key from receiver)
sender:
	@echo "Starting Sender on http://127.0.0.1:8080..."
	@echo "  Receiver TCP target: 127.0.0.1:9999"
	@echo "  Receiver HTTP API: http://127.0.0.1:8081"
	@echo "  (Make sure receiver is already running!)"
	@$(PYTHON) sender_api.py --port=8080

# Start receiver (http://localhost:8081, TCP on 9999) — C/S split architecture
# Generates RSA keypair on first startup, exposes public key via HTTP API
receiver:
	@echo "Starting Receiver HTTP on http://127.0.0.1:8081..."
	@echo "  Receiver TCP on 127.0.0.1:9999..."
	@echo "  RSA keypair will be generated automatically (may take a few seconds)"
	@$(PYTHON) receiver_api.py --port=8081 --tcp-port=9999

# Lint check: syntax + compilation (stdlib only)
lint:
	@echo "Running zero-dependency lint..."
	@$(PYTHON) lint_check.py

# Done checklist: verify docs synced before commit
# Must be run BEFORE git add (or after, with --all)
done:
	@echo "Running pre-commit done checklist..."
	@$(PYTHON) done_check.py

# Setup git hooks (run once per clone)
setup-hooks:
	@echo "Setting up git hooks path..."
	@git config core.hooksPath hooks
	@echo "Done. hooks/pre-commit will run on every 'git commit'."
	@echo "Override with: git commit --no-verify"
