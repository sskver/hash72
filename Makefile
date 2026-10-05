FIRMWARE ?= ../
SAMPLES  ?= 3400
FIT      ?= 2400

.PHONY: tables build test clean

tables: tables.go

tables.go:
	python3 dump/dump_tables.py \
	  --retail $(FIRMWARE)osos5g_retail.bin \
	  --stub   $(FIRMWARE)osos5g_stub.bin \
	  --out    tables.go \
	  --samples $(SAMPLES) --fit $(FIT)

build: tables.go
	go build ./...

test: tables.go
	go test ./...

clean:
	rm -f tables.go hash72
