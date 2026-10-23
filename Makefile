BIN := easalt
VERSION := 1.0.6
DIST := dist

.PHONY: build test bench release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) .

vet:
	gofmt -l . && go vet ./...

release: clean
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(DIST)/$(BIN)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(DIST)/$(BIN)-linux-arm64 .
	@cp esalat.sh $(DIST)/esalat.sh
	@for arch in amd64 arm64; do \
	  d=$(DIST)/esalat-tunnel-$(VERSION)-linux-$$arch; mkdir -p $$d; \
	  cp $(DIST)/$(BIN)-linux-$$arch $$d/easalt; \
	  cp esalat.sh README.md README-fa.md LICENSE $$d/ 2>/dev/null || true; \
	  tar -czf $$d.tar.gz -C $(DIST) $$(basename $$d); \
	  echo "built $$d.tar.gz"; \
	done
	@sha256sum $(DIST)/*.tar.gz | tee $(DIST)/SHA256SUMS

clean:
	rm -rf $(DIST)
