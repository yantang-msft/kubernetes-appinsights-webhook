
build:
	GOOS=linux GOARCH=amd64 go build -a -o webhook .
	