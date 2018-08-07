// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under MIT License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
)

const (
	addIKeyPlainTextPatch string = ` {
        "op": "add",
        "path": "/spec/containers/%d/env/-",
        "value": {
            "name": "APPINSIGHTS_INSTRUMENTATIONKEY",
            "value": "%s"
        }
    }
	`

	addEnvWithIKeyPlainTextPatch string = ` {
        "op": "add",
        "path": "/spec/containers/%d/env",
        "value": [
            {
                "name": "APPINSIGHTS_INSTRUMENTATIONKEY",
                "value": "%s"
            }
        ]
    }
    `

	addIKeyFromSecretPatch string = `{
        "op": "add",
        "path": "/spec/containers/%d/env/-",
        "value": {
            "name": "APPINSIGHTS_INSTRUMENTATIONKEY",
            "valueFrom": {
                "secretKeyRef": {
                    "name": "%s",
                    "key": "APPINSIGHTS_INSTRUMENTATIONKEY"
                }
            }
        }
    }`

	addEnvWithIKeyFromSecretPatch string = `{
        "op": "add",
        "path": "/spec/containers/%d/env",
        "value": [
            {
                "name": "APPINSIGHTS_INSTRUMENTATIONKEY",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "%s",
                        "key": "APPINSIGHTS_INSTRUMENTATIONKEY"
                    }
                }
            }
        ]
    }`

	addEndpointPatch string = ` {
        "op": "add",
        "path": "/spec/containers/%d/env/-",
        "value": {
            "name": "APPINSIGHTS_ENDPOINT",
            "value": "%s"
        }
    }
	`

	updateEndpointPatch string = ` {
        "op": "replace",
        "path": "/spec/containers/%d/env/%d",
        "value": {
            "name": "APPINSIGHTS_ENDPOINT",
            "value": "%s"
        }
    }
	`

	// TODO: need a better way to detect whether we need to add the volume mount
	addFluentdSidecarPlainTextIKeyPatch string = ` {
        "op": "add",
        "path": "/spec/containers/-",
        "value": {
            "name": "fluentdsidecar",
            "image": "yanmingacr.azurecr.io/fluentdsidecar",
            "env": [{
                    "name": "APPINSIGHTS_INSTRUMENTATIONKEY",
                    "value": "%s"
                }, {
                    "name": "NAMESPACE_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.namespace"
                        }
                    }
                }, {
                    "name": "POD_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.name"
                        }
                    }
                }, {
                    "name": "SOURCE_CONTAINER_NAME",
                    "value": "%s"
                }, {
                    "name": "FLUENTD_OPT",
                    "value": "-v"
            }],
            "volumeMounts": [
                {
                    "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                    "name": "%s",
                    "readOnly": true
                }
            ]
        }
    }
	`

	// TODO: keep this snippet up to date
	addFluentdSidecarIKeyFromSecretPatch string = ` {
        "op": "add",
        "path": "/spec/containers/-",
        "value": {
            "name": "fluentdsidecar",
            "image": "yanmingacr.azurecr.io/fluentdsidecar",
            "env": [{
                    "name": "APPINSIGHTS_INSTRUMENTATIONKEY",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": "%s",
                            "key": "APPINSIGHTS_INSTRUMENTATIONKEY"
                        }
                    }
                }, {
                    "name": "NAMESPACE_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.namespace"
                        }
                    }
                }, {
                    "name": "POD_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.name"
                        }
                    }
                }, {
                    "name": "SOURCE_CONTAINER_NAME",
                    "value": "%s"
                }, {
                    "name": "FLUENTD_OPT",
                    "value": "-v"
            }]
        }
    }
	`

	// IKeyVarName is the well-known name for Application Insights insrumentation key environment variable
	IKeyVarName string = "APPINSIGHTS_INSTRUMENTATIONKEY"

	// EndpointVarName is the well-know name for Application Insights SDK's endpoint address
	EndpointVarName string = "APPINSIGHTS_ENDPOINT"

	// TODO: We need dynamic endpoint address if there are multiple containers
	EndpointVarValue string = "http://localhost:8887/ApplicationInsightsHttpChannel"

	// KubeSystemNamespace is the Kubernetes system namespace name. We disregard objects in that namespace.
	KubeSystemNamespace = "kube-system"

	// AppInsightsClusterResource is the secret name that store the ikey of the cluster Application Insights resource
	AppInsightsClusterResource = "applicationinsights-cluster-resource"

	// AppInsightsInfoAnnotation contains instrumentation key and other information related to sending telemetry to Azure Application Insights
	AppInsightsInfoAnnotation = "azure.microsoft.com/applicationinsights-info"
)

type admitFunc func(v1beta1.AdmissionReview) (response *v1beta1.AdmissionResponse, trackDetails bool)

var (
	// TODO: periodically load information about all secrets in the system
	// and compare this information with what we have cached in the aiSecrets slice.

	aiSecrets       = make([]appInsightsSecret, 1)
	aiClusterSecret appInsightsSecret
	aiSecretsLock   sync.RWMutex

	// AllowUnchanged is a standard response instructing Kubernetes to allow the object in its original form
	// NOTE: this webhook should never PREVENT any operation from happening, so in case of most unexpected errors
	// we log the error, but then return AllowUnchanged. Only fatal errors return an actuall admission error response.
	AllowUnchanged = v1beta1.AdmissionResponse{Allowed: true}

	decoder = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()

	clientset *kubernetes.Clientset
)

func toErrorResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func admitSecrets(ar v1beta1.AdmissionReview) (_ *v1beta1.AdmissionResponse, trackDetails bool) {
	secretResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	if currentResource := ar.Request.Resource; currentResource != secretResource {
		glog.Warningf("Expected resource to be a secret but it is a '%s' (group '%s', version %s)",
			currentResource.Resource, currentResource.Group, currentResource.Version)
		return &AllowUnchanged, true
	}

	secret := corev1.Secret{}
	operation := ar.Request.Operation

	if operation == v1beta1.Create || operation == v1beta1.Update {
		if _, _, err := decoder.Decode(ar.Request.Object.Raw, nil, &secret); err != nil {
			glog.Error(err)
			return &AllowUnchanged, true
		}
	}

	if operation == v1beta1.Create {
		glog.V(2).Infof("Admitting new secret %s.%s", secret.Namespace, secret.Name)
		trackDetails = handleSecretCreation(secret)
	} else if operation == v1beta1.Delete {
		glog.V(2).Infof("Secret %s.%s is being deleted", ar.Request.Namespace, ar.Request.Name)
		trackDetails = handleSecretRemoval(ar.Request.Name, ar.Request.Namespace)
	} else if operation == v1beta1.Update {
		glog.V(2).Infof("Secret %s.%s is being updated", secret.Namespace, secret.Name)

		interestingRemoval := handleSecretRemoval(ar.Request.Name, ar.Request.Namespace)
		interestingCreation := handleSecretCreation(secret)
		trackDetails = interestingRemoval || interestingCreation
	}

	return &AllowUnchanged, trackDetails
}

func handleSecretRemoval(secretName string, secretNamespace string) (trackDetails bool) {
	// Taking a lock now ensures stable iteration over aiSecrets
	aiSecretsLock.Lock()
	defer aiSecretsLock.Unlock()

	newSecrets := make([]appInsightsSecret, len(aiSecrets))
	i := 0
	for _, aiSecret := range aiSecrets {
		if aiSecret.Name == secretName && aiSecret.Namespace == secretNamespace {
			glog.V(2).Infof("Removing cached data for secret %s.%s", secretNamespace, secretName)
			trackDetails = true
			continue
		}

		newSecrets[i] = aiSecret
		i++
	}

	aiSecrets = newSecrets
	return trackDetails
}

func handleSecretCreation(secret corev1.Secret) (trackDetails bool) {
	if secret.Namespace == KubeSystemNamespace && secret.Name == AppInsightsClusterResource {
		aiClusterSecret.Name = secret.Name
		aiClusterSecret.Namespace = secret.Namespace
		aiClusterSecret.CreationTimestamp = secret.CreationTimestamp
		// The secret data is already decoded
		aiClusterSecret.InstrumentationKey = string(secret.Data[IKeyVarName])
	} else {
		ais, err := toAppInsightsSecretInfo(secret)
		if err != nil {
			return true // Conversion failed--track details
		}
		if ais == nil {
			return false // Secret does not contain Application Insights info
		}

		aiSecretsLock.Lock()
		defer aiSecretsLock.Unlock()
		aiSecrets = append(aiSecrets, *ais)
	}

	return true
}

func mutatePods(ar v1beta1.AdmissionReview) (_ *v1beta1.AdmissionResponse, trackDetails bool) {
	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if currentResource := ar.Request.Resource; currentResource != podResource {
		glog.Warningf("Expected resource to be a pod but it is a '%s' (group '%s', version %s)",
			currentResource.Resource, currentResource.Group, currentResource.Version)
		return &AllowUnchanged, true
	}

	if ar.Request.Operation != v1beta1.Create && ar.Request.Operation != v1beta1.Update {
		glog.V(2).Infof("Operation on the pod is %s, allowing unchanged", ar.Request.Operation)
		return &AllowUnchanged, false
	}

	// Note: for the "update" operation ar.Request.Object is the "new" object vs. ar.Request.OldObject.
	// So whether it is a "create" operation, or "update" operation, ar.Request.Object is the right one to examine.
	pod := corev1.Pod{}
	if _, _, err := decoder.Decode(ar.Request.Object.Raw, nil, &pod); err != nil {
		glog.Error(err)
		return &AllowUnchanged, true
	}

	if pod.Namespace == KubeSystemNamespace {
		return &AllowUnchanged, false
	}

	var podName string
	switch {
	case len(pod.Name) > 0:
		podName = pod.Name
	case len(pod.GenerateName) > 0:
		podName = pod.GenerateName
	default:
		podName = "(unknown)"
	}

	glog.V(2).Infof("Admitting pod %s.%s ...", ar.Request.Namespace, podName)

	aiSecretsLock.RLock()
	defer aiSecretsLock.RUnlock()

	// Iterate aiSecrets slice backwards so that latest secrets are preferred
	for si := len(aiSecrets) - 1; si >= 0; si-- {
		secret := aiSecrets[si]

		if secret.Namespace != ar.Request.Namespace {
			continue
		}

		for lsi, labelSelector := range secret.Annotation.Selectors {
			selector, err := metav1.LabelSelectorAsSelector(&labelSelector)
			if err != nil {
				glog.Warningf(
					"Unexpected error when trying to use secret %s.%s. LabelSelector nr %d (%s) could not be converted to a Selector. %s",
					secret.Namespace, secret.Name, lsi, metav1.FormatLabelSelector(&labelSelector), err)
				continue
			}

			if selector.Matches(labels.Set(pod.Labels)) {
				glog.V(2).Infof("Using secret %s to inject AppInsights iKey into pod %s.%s (selector nr %d matches)",
					secret.Name, ar.Request.Namespace, podName, lsi)
				return createPatchResponse(pod, podName, secret), true
			}
		}
	}

	// TODO: need a better way to check if cluster secret is there or not
	if aiClusterSecret.InstrumentationKey != "" {
		return createPatchResponse(pod, podName, aiClusterSecret), true
	}

	glog.V(2).Infof("No matching secrets found for pod %s.%s, allowing unchanged", ar.Request.Namespace, podName)
	return &AllowUnchanged, false
}

func createPatchResponse(pod corev1.Pod, podName string, secret appInsightsSecret) *v1beta1.AdmissionResponse {
	response := v1beta1.AdmissionResponse{}
	response.Allowed = true
	patchList := getPatches(pod, podName, secret)

	if len(patchList) > 0 {
		patchStr := "[\n" + strings.Join(patchList, ",\n ") + "\n]"
		glog.V(2).Infof("Patching request for pod %s is: %s", podName, patchStr)
		response.Patch = []byte(patchStr)
		pt := v1beta1.PatchTypeJSONPatch
		response.PatchType = &pt
	} else {
		glog.V(2).Infof("None of the containers inside pod %s required patching to add instrumentation key variable", podName)
	}

	return &response
}

func getPatches(pod corev1.Pod, podName string, secret appInsightsSecret) []string {
	patchList := []string{}

	for containerIndex, container := range pod.Spec.Containers {
		// Make sure we do not patch if the AppInsights instrumentation key is already set on the pod
		iKeyVarExists := false
		for _, envVar := range container.Env {
			if envVar.Name == IKeyVarName {
				glog.V(2).Infof(
					"Container %s of pod %s already has an instrumentation key variable, skipping",
					container.Name, podName)

				iKeyVarExists = true
				break
			}
		}
		if iKeyVarExists {
			continue
		}

		if len(container.Env) > 0 {
			// TODO: better way to discriminate or inject cluster level ikey vs app level ikey
			if secret.InstrumentationKey != "" {
				patchList = append(patchList, fmt.Sprintf(addIKeyPlainTextPatch, containerIndex, secret.InstrumentationKey))
			} else {
				patchList = append(patchList, fmt.Sprintf(addIKeyFromSecretPatch, containerIndex, secret.Name))
			}
		} else {
			if secret.InstrumentationKey != "" {
				patchList = append(patchList, fmt.Sprintf(addEnvWithIKeyPlainTextPatch, containerIndex, secret.InstrumentationKey))
			} else {
				patchList = append(patchList, fmt.Sprintf(addEnvWithIKeyFromSecretPatch, containerIndex, secret.Name))
			}
		}

		// TODO: Will need different endpoint if there are multiple containers, thus sidecars
		if containerIndex > 0 {
			continue
		}

		// Add AppInsights_Endpoint environment variable
		endpointVarExists := false
		for endpointEnvIndex, envVar := range container.Env {
			if envVar.Name == EndpointVarName {
				glog.V(2).Infof(
					"Container %s of pod %s already has an instrumentation key variable, skipping",
					container.Name, podName)
				patchList = append(patchList, fmt.Sprintf(updateEndpointPatch, containerIndex, endpointEnvIndex, EndpointVarValue))
				endpointVarExists = true
				break
			}
		}
		if !endpointVarExists {
			patchList = append(patchList, fmt.Sprintf(addEndpointPatch, containerIndex, EndpointVarValue))
		}

		// Add side car container
		// TODO: For demo purpose, only inject the sidecar if there isn't a sidecar already and only inject for the first container
		volumeMountName := "tmp"
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
				volumeMountName = mount.Name
				break
			}
		}
		if secret.InstrumentationKey != "" {
			patchList = append(patchList, fmt.Sprintf(addFluentdSidecarPlainTextIKeyPatch, secret.InstrumentationKey, container.Name, volumeMountName))
		} else {
			patchList = append(patchList, fmt.Sprintf(addFluentdSidecarIKeyFromSecretPatch, secret.Name, container.Name))
		}
	}

	return patchList
}

func serve(w http.ResponseWriter, r *http.Request, admit admitFunc) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("No request body found")
		http.Error(w, "No request body found", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("contentType=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, want `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	ar := v1beta1.AdmissionReview{}
	if _, _, err := decoder.Decode(body, nil, &ar); err != nil {
		glog.Error(err)
		http.Error(w, "Could not decode the request as AdmissionReview", http.StatusBadRequest)
		return
	}

	reviewResponse, trackDetails := admit(ar)

	response := v1beta1.AdmissionReview{}
	response.Response = reviewResponse
	response.Response.UID = ar.Request.UID

	if glog.V(2) {
		if trackDetails {
			dumpJSON("The raw request was: %s", body)
		}
		if len(reviewResponse.Patch) > 0 {
			dumpJSON("Sending patch response: %s", reviewResponse.Patch)
		}
	}

	resp, err := json.Marshal(response)
	if err != nil {
		glog.Error(err)
		http.Error(w, fmt.Sprintf("Could not encode response: %v", err), http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(resp); err != nil {
		glog.Error(err)
		http.Error(w, fmt.Sprintf("Could not write response: %v", err), http.StatusInternalServerError)
	}
}

func serveSecrets(w http.ResponseWriter, r *http.Request) {
	serve(w, r, admitSecrets)
}

func serveMutatePods(w http.ResponseWriter, r *http.Request) {
	serve(w, r, mutatePods)
}

func serveHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func refreshSecrets() error {
	glog.V(2).Info("Querying Kubernetes for new secrets...")

	var timeout int64 = 5
	secrets, err := clientset.CoreV1().Secrets("").List(metav1.ListOptions{TimeoutSeconds: &timeout})
	if err != nil {
		glog.Warningf("Could not refresh secret information: %v", err)
		return nil
	}

	newSecrets := make([]appInsightsSecret, len(aiSecrets))

	aiSecretsLock.Lock()
	defer aiSecretsLock.Unlock()

	for _, secret := range secrets.Items {
		if secret.Namespace == KubeSystemNamespace && secret.Name == AppInsightsClusterResource {
			aiClusterSecret.Name = secret.Name
			aiClusterSecret.Namespace = secret.Namespace
			aiClusterSecret.CreationTimestamp = secret.CreationTimestamp
			// The secret data is already decoded
			aiClusterSecret.InstrumentationKey = string(secret.Data[IKeyVarName])
			glog.V(2).Infof("Adding cluster AI resource Secret %s", secret.Name)
		} else {
			ais, err := toAppInsightsSecretInfo(secret)
			if err != nil || ais == nil {
				continue
			}
			newSecrets = append(newSecrets, *ais)
		}
	}

	sort.Sort(byCreationTimestamp(newSecrets))
	aiSecrets = newSecrets

	return nil
}

func main() {
	flag.Parse() // Required to parse glog flags

	// CONSIDER Make the cert file location configurable
	exec, err := os.Executable()
	if err != nil {
		glog.Fatalf("Could not get executable path: %s", err)
	}

	base := filepath.Dir(exec)
	certFile := filepath.Join(base, "certs/tls.crt")
	keyFile := filepath.Join(base, "certs/tls.key")

	http.HandleFunc("/secrets", serveSecrets)
	http.HandleFunc("/mutating-pods", serveMutatePods)
	http.HandleFunc("/health", serveHealth)

	clientset = getClient()
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: configTLS(certFile, keyFile, clientset),
	}

	doneC := make(chan error, 2)
	signalC := make(chan os.Signal, 1)

	secretRefreshC := repeat(refreshSecrets, time.Duration(30)*time.Second, doneC)

	go func() {
		glog.V(2).Info("Certificates loaded. Listening for requests...")
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			glog.Error(err)
			doneC <- err
		} else {
			doneC <- nil
		}
	}()

	signal.Notify(signalC, os.Interrupt, syscall.SIGTERM)
	go func() {
		var err error

		select {
		case <-signalC:
			glog.V(2).Info("Exiting gracefully...")
			// Instruct the secret refresh process and the HTTPS server to shut down
			close(secretRefreshC)
			if err := server.Close(); err != nil {
				glog.Error(err)
			}

		case err = <-doneC:
			glog.Fatalf("Unexpected error occurred, aborting: %v", err)
		}
	}()

	// Wait for HTTPS server and secret refresh process to finish cleanup
	<-doneC
	<-doneC
	glog.V(2).Info("Shutdown complete")
}
