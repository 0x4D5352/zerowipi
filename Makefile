build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -trimpath -o zwp

deploy:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -trimpath -ldflags="-s -w" -o zwp

test:
	go build -o zwp

clean:
	rm zwp
