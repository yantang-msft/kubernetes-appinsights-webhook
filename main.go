// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under MIT License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	addIKeyVarPatch string = `[
         {"op":"add","path":"/spec/initContainers","value":[{"image":"webhook-added-image","name":"webhook-added-init-container","resources":{}}]}
    ]`

	// IKeyVarName is the well-known name for Application Insights insrumentation key environment variable
	IKeyVarName string = "APPINSIGHTS_INSTRUMENTATIONKEY"
)

// Config contains the server (the webhook) cert and key.
type Config struct {
	CertFile string
	KeyFile  string
}

// Data about a secret that contains Application Insights instrumentation key and other AppInsights configuration data.
type appInsightsSecret struct {
	Selector  metav1.LabelSelector
	Name      string
	Namespace string
}

type admitFunc func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

var (
	aiSecrets     []appInsightsSecret
	aiSecretsLock sync.RWMutex

	// AllowUnchanged is a standard response instructing Kubernetes to allow the object in its original form
	AllowUnchanged v1beta1.AdmissionResponse
)

func (c *Config) addFlags() {
	flag.StringVar(&c.CertFile, "tls-cert-file", c.CertFile, "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert).")
	flag.StringVar(&c.KeyFile, "tls-private-key-file", c.KeyFile, "File containing the default x509 private key matching --tls-cert-file.")
}

func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func admitSecrets(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	secretResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	if currentResource := ar.Request.Resource; currentResource != secretResource {
		err := fmt.Errorf("Expected resource to be a secret but it is a '%s' (group '%s', version %s)",
			currentResource.Resource, currentResource.Group, currentResource.Version)
		glog.Error(err)
		return toAdmissionResponse(err)
	}

	raw := ar.Request.Object.Raw
	secret := corev1.Secret{}
	if err := json.Unmarshal(raw, &secret); err != nil {
		glog.Error(err)
		return toAdmissionResponse(err)
	}

	if ar.Request.Operation == v1beta1.Create {
		glog.V(2).Infof("Admitting new secret %s.%s ...", secret.Namespace, secret.Name)
		handleSecretCreation(secret)
	}

	// TODO handle secret update and deletion

	return &AllowUnchanged
}

func handleSecretRemoval(secret corev1.Secret) {

}

func handleSecretCreation(secret corev1.Secret) {
	if _, iKeyPresent := secret.Data[IKeyVarName]; !iKeyPresent {
		glog.V(2).Infof("Secret %s does not have %s in its data", secret.Name, IKeyVarName)
		return
	}

	if len(secret.Labels) == 0 {
		glog.Warningf("Cannot identify pods to use with secret %s.%s because the secret does not have any labels",
			secret.Namespace, secret.Name)
		return
	}

	glog.V(2).Infof("Adding %s to list of secrets with AppInsights key information", secret.Name)
	ais := appInsightsSecret{}
	ais.Name = secret.Name
	ais.Namespace = secret.Namespace
	// Here we will just gather all the labels on the secret and use them as a label selector to identify the pods
	// that should be injected with instrumentation key information
	//
	// CONSIDER having a well-known annotation that contains a label selector that identifies the pods explicitly.
	// This annotation could be optional, and the "use secret labels as a label selector" could be used by default
	ais.Selector = metav1.LabelSelector{}
	for lName, lValue := range secret.Labels {
		glog.V(2).Infof("Pods that use secret %s must have label %s with value %s", secret.Name, lName, lValue)
		metav1.AddLabelToSelector(&ais.Selector, lName, lValue)
	}

	aiSecretsLock.Lock()
	defer aiSecretsLock.Unlock()
	aiSecrets = append(aiSecrets, ais)
}

func mutatePods(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if currentResource := ar.Request.Resource; currentResource != podResource {
		err := fmt.Errorf("Expected resource to be a oid but it is a '%s' (group '%s', version %s)",
			currentResource.Resource, currentResource.Group, currentResource.Version)
		glog.Error(err)
		return toAdmissionResponse(err)
	}

	raw := ar.Request.Object.Raw
	pod := corev1.Pod{}
	if err := json.Unmarshal(raw, &pod); err != nil {
		glog.Error(err)
		return toAdmissionResponse(err)
	}
	glog.V(2).Infof("Admitting pod %s.%s ...", pod.Namespace, pod.Name)

	if ar.Request.Operation != v1beta1.Create && ar.Request.Operation != v1beta1.Update {
		glog.V(2).Infof("Operation on the pod %s is %s, allowing unchanged", pod.Name, ar.Request.Operation)
		return &AllowUnchanged
	}

	response := v1beta1.AdmissionResponse{}
	response.Allowed = true

	aiSecretsLock.RLock()
	defer aiSecretsLock.RUnlock()

	// Iterate aiSecrets slice backwards so that latest secrets are preferred
	for i := len(aiSecrets) - 1; i >= 0; i-- {
		selector, err := metav1.LabelSelectorAsSelector(&aiSecrets[i].Selector)
		if err != nil {
			glog.Warningf("One of the stored LabelSelectors could not be converted to a Selector: %s", err)
			continue
		}

		if selector.Matches(labels.Set(pod.Labels)) {
			// We have found a secret that has a matching set of labels with the pod.

			for cIndex, container := range pod.Spec.Containers {

				// Make sure we do not patch if the AppInsights instrumentation key is already set on the pod
				iKeyVarExists := false
				for _, envVar := range container.Env {
					if envVar.Name == IKeyVarName {
						iKeyVarExists = true
						break
					}
				}
				if iKeyVarExists {
					continue
				}

				// TODO: add patch to list of patches
			}

			response.Patch = "" // TODO: construct patch array properly
			response.PatchType

			// We found a matching secret and we patched all containers as necessary.
			// There is nothing more left to do for this pod.
			break
		}
	}

	return &response

	/*
	   reviewResponse := v1beta1.AdmissionResponse{}
	   reviewResponse.Allowed = true
	   if pod.Name == "webhook-to-be-mutated" {
	       reviewResponse.Patch = []byte(addInitContainerPatch)
	       pt := v1beta1.PatchTypeJSONPatch
	       reviewResponse.PatchType = &pt
	   }
	   return &reviewResponse
	*/

	return &reviewResponse
}

func serve(w http.ResponseWriter, r *http.Request, admit admitFunc) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("contentType=%s, expect application/json", contentType)
		return
	}

	glog.V(2).Info(fmt.Sprintf("Handling request: %v", body))
	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(body, &ar); err != nil {
		glog.Error(err)
		reviewResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		reviewResponse = admit(ar)
	}
	glog.V(2).Info(fmt.Sprintf("Sending response: %v", reviewResponse))

	response := v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		response.Response.UID = ar.Request.UID
	}
	// reset the Object and OldObject, they are not needed in a response.
	ar.Request.Object = runtime.RawExtension{}
	ar.Request.OldObject = runtime.RawExtension{}

	resp, err := json.Marshal(response)
	if err != nil {
		glog.Error(err)
	}
	if _, err := w.Write(resp); err != nil {
		glog.Error(err)
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

func main() {
	var config Config
	config.addFlags()
	flag.Parse()

	AllowUnchanged = v1beta1.AdmissionResponse{Allowed: true}

	aiSecrets = make([]appInsightsSecret, 1)

	http.HandleFunc("/secrets", serveSecrets)
	http.HandleFunc("/mutating-pods", serveMutatePods)
	http.HandleFunc("/health", serveHealth)

	clientset := getClient()
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: configTLS(config, clientset),
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		glog.Fatal(err)
	}
}
