PYTHON ?= ../.venv/bin/python
PIP    ?= ../.venv/bin/pip
SCOPE  ?= scope.yaml

.PHONY: install test health check run keys

install:
	$(PIP) install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

health:
	$(PYTHON) -m critforge.cli health --scope $(SCOPE)

check:
	$(PYTHON) -m critforge.cli check --scope $(SCOPE) $(TARGET)

run:
	$(PYTHON) -m critforge.cli run --scope $(SCOPE) $(ARGS)

keys:
	$(PYTHON) -m critforge.cli keys --secrets secrets.yaml --bootstrap
