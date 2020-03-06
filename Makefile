REPO_NAME  := $(shell git config --get-regexp remote.origin.url | sed "s/.*dusk-network\/\(.*\)\.git/\1/")
PACKAGE_NAME := $(shell cargo metadata --no-deps --format-version=1 | python -c "import sys, json; print json.load(sys.stdin)['packages'][0]['name']")
REPO_BADGE_URL := "https://img.shields.io/badge/github-$(shell echo $(REPO_NAME) | sed "s/-/--/g")-brightgreen?logo=github"
META := "<meta http-equiv=refresh content=0;url=./$(shell echo $(PACKAGE_NAME) | sed "s/-/_/g")/index.html>"

define generate_docs 
	@echo $(META) > target/doc/index.html && \
	curl -o 'target/doc/badge.svg' 'https://img.shields.io/badge/docs-latest-blue?logo=rust' && \
	curl -o 'target/doc/repo-badge.svg' $(REPO_BADGE_URL) && \
	curl -L https://github.com/davisp/ghp-import/archive/master.tar.gz | tar --strip-components 1 -C $1 -xz
	$1/ghp_import.py -n target/doc
	rm -rf $1
endef

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

doc: ## Generate documentation
	@cargo rustdoc --lib

doc-internal: ## Generate documentation with private items
	@cargo rustdoc --lib -- --document-private-items

publish-doc: ### Publish the documentation as github pages
	@$(call generate_docs, $(shell mktemp -d)) && \
	git push -f https://github.com/dusk-network/$(REPO_NAME) gh-pages

.PHONY: help doc doc-internal publish-doc