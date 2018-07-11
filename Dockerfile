
FROM alpine:latest

RUN apk --update add ca-certificates && adduser -D aiwebhook

COPY appinsights-webhook /home/aiwebhook/appinsights-webhook
RUN chown -R aiwebhook /home/aiwebhook/appinsights-webhook && chmod o+x /home/aiwebhook/appinsights-webhook

USER aiwebhook
ENTRYPOINT [ "/home/aiwebhook/appinsights-webhook" ]
