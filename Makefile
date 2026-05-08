.PHONY: build test acceptance fmt lint vet release clean

BINARY := vault-plugin-secrets-argon2
PKG    := ./cmd/$(BINARY)

build:
	go build -trimpath -o $(BINARY) $(PKG)

test:
	go test -race -short ./...

# Acceptance tests run the full path suite (no -short flag).
# Argon2id is intentionally CPU-heavy, so this target takes longer.
acceptance:
	go test -race ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

# Local release build for all supported OS/arch pairs. The release
# pipeline produces signed artifacts with SLSA provenance — this
# target is for local smoke testing only.
release:
	@for goos in linux darwin; do \
	  for goarch in amd64 arm64; do \
	    out=dist/$(BINARY)-$$goos-$$goarch ; \
	    echo "Building $$out" ; \
	    GOOS=$$goos GOARCH=$$goarch go build -trimpath -o $$out $(PKG) || exit 1 ; \
	  done ; \
	done

clean:
	rm -rf $(BINARY) dist/ coverage.out
