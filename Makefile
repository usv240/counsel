.PHONY: help install demo test redteam serve clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Install COUNSEL in editable mode
	pip install -e .

demo:  ## Run the no-API demonstration (judges start here - no ANTHROPIC_API_KEY needed)
	counsel demo

test:  ## Run the full test suite (58 tests, no API key needed)
	python -m pytest tests/ -q

redteam:  ## Run the architectural red-team suite (RT1-RT9)
	counsel redteam ./counsel/fixtures/szechuan_sauce

serve:  ## Start the web dashboard at http://localhost:8000
	counsel serve

clean:  ## Remove generated run output
	rm -rf counsel-output/
