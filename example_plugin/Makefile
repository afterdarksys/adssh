PLUGIN_SRC=plugin.go
PLUGIN_OUT=plugin.so

all: build

build:
	go build -buildmode=plugin -o $(PLUGIN_OUT) $(PLUGIN_SRC)

clean:
	rm -f $(PLUGIN_OUT)
