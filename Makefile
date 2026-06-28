.PHONY: all install test train run clean clean-generated p4-compile p4-clean verify-strategies verify-int verify-int-reverse

# Project directories
P4_DIR := p4
P4_BUILD := $(P4_DIR)/build
PYTHON_DIR := python
EXPERIMENTS_DIR := experiments

# P4 compiler settings
P4C := p4c
P4C_FLAGS := --target bmv2 --arch v1model

# Python
PYTHON := python

all: install

install:
	@echo "Installing Python dependencies..."
	$(PYTHON) -m pip install -r requirements.txt

# ===== P4 Compilation =====

p4-compile:
	@echo "Compiling P4 program for 2-switch 3-link topology..."
	@mkdir -p $(P4_BUILD)
	$(P4C) $(P4C_FLAGS) --output $(P4_BUILD)/covert_int_switch.json $(P4_DIR)/covert_int_switch.p4
	@echo "P4 compilation complete."

p4-clean:
	@rm -rf $(P4_BUILD)/*.json

# ===== Testing =====

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

test-cov:
	$(PYTHON) -m pytest tests/ -v --cov=$(PYTHON_DIR) --cov-report=html

# ===== RL Training =====

train:
	$(PYTHON) $(EXPERIMENTS_DIR)/train_rl_agent.py --config $(EXPERIMENTS_DIR)/configs/default.yaml

# ===== Experiments =====

verify-strategies:
	$(PYTHON) scripts/verify_all_strategies.py --input $(EXPERIMENTS_DIR)/data/input_message.txt --output-dir $(EXPERIMENTS_DIR)/results

verify-int:
	$(PYTHON) $(EXPERIMENTS_DIR)/verify_int_pipeline.py --output $(EXPERIMENTS_DIR)/results/int_state.json

verify-int-reverse:
	$(PYTHON) $(EXPERIMENTS_DIR)/verify_int_pipeline.py --direction reverse --output $(EXPERIMENTS_DIR)/results/reverse_int_state.json

run-experiment:
	$(PYTHON) $(EXPERIMENTS_DIR)/run_experiment.py --config $(EXPERIMENTS_DIR)/configs/default.yaml

# ===== Cleanup =====

clean:
	@rm -rf __pycache__ **/__pycache__ **/**/__pycache__
	@rm -rf .pytest_cache
	@rm -rf logs/
	@rm -rf $(EXPERIMENTS_DIR)/results/summary/*
	@rm -rf $(EXPERIMENTS_DIR)/results/plots/*

clean-generated:
	@rm -f $(EXPERIMENTS_DIR)/results/*.json
	@rm -f $(EXPERIMENTS_DIR)/results/*.csv
	@rm -f $(EXPERIMENTS_DIR)/results/*.bin
	@rm -f $(EXPERIMENTS_DIR)/results/*.pcap

# ===== Help =====

help:
	@echo "Available targets:"
	@echo "  install       - Install Python dependencies"
	@echo "  p4-compile    - Compile P4 programs to BMv2 JSON"
	@echo "  p4-clean      - Remove compiled P4 output"
	@echo "  test          - Run Python unit tests"
	@echo "  test-cov      - Run tests with coverage report"
	@echo "  verify-strategies - Verify all five covert strategies and generate traces/pcap"
	@echo "  verify-int    - Verify INT parser and link-state calculation"
	@echo "  verify-int-reverse - Verify reverse active INT probing calculation"
	@echo "  train         - Train the PPO RL agent"
	@echo "  run-experiment- Run full experiment"
	@echo "  clean         - Remove generated files"
	@echo "  clean-generated - Remove generated strategy verification outputs"
