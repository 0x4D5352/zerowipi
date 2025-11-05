build:
	GOOS=linux GOARCH=arm GOARM=6 go build -o zwp

test:
	go build -o zwp

clean:
	rm zwp
