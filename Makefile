setup:
	bash setup-check.sh

run:
	bash run.sh

backend:
	@echo "[deprecated] Use ./run.sh from the project root." >&2
	@exit 1

frontend:
	@echo "[deprecated] Use ./run.sh from the project root." >&2
	@exit 1

sensor:
	@echo "[deprecated] Use ./run.sh from the project root." >&2
	@exit 1
