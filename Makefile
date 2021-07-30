build:
	docker build -t fanfiction_ff_proxy .

run: build
	docker run --rm -p 8888:8888 -p 8080:8080 fanfiction_ff_proxy

shell: build
	docker run --rm -ti -p 8888:8888 -p 8080:8080 fanfiction_ff_proxy bash

clean:
	docker image rm fanfiction_ff_proxy
