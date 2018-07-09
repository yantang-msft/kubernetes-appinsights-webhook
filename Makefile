
IMAGE = appinsights-webhook
TAG = 0.1

build:
	GOOS=linux GOARCH=amd64 go build -a -o appinsights-webhook .
	docker build --no-cache -t $(IMAGE):$(TAG) .
	rm -f appinsights-webhook