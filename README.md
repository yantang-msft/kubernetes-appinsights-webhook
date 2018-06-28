# Introduction 
A Kubernetes mutating admission webhook for injecting Application Insights-related resources,
such as environment variables, into application pods.

# How it works
The webhook is watching for secrets with a label selector given by the configuration.
When a matching secret is encountered, the hook will memorize it and start looking for pods
matching the same label selector.
When such pod is being created, the webhook will inject all keys from the secret
into the pod, using environment variables. It works in a way similar to PodPreset.

# Build 

# Setup

