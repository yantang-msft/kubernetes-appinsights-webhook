
FROM alpine:latest

RUN apk --update add ca-certificates

COPY appinsights-webhook /home/aiwebhook/appinsights-webhook

ENTRYPOINT [ "/home/aiwebhook/appinsights-webhook" ]
