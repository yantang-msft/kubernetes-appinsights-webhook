
FROM alpine:latest

ADD appinsights-webhook /appinsights-webhook
ENTRYPOINT [ "/appinsights-webhook" ]
