
REPO = yanmingacr.azurecr.io/
IMAGE = appinsights-webhook
TAG = latest

build:
	GOOS=linux GOARCH=amd64 go build -a -o appinsights-webhook .
	docker build --no-cache -t $(REPO)$(IMAGE):$(TAG) .
	docker push $(REPO)$(IMAGE):$(TAG)
	rm -f appinsights-webhook