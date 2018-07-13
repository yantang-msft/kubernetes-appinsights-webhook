// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under MIT License.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	addIKeyVarPatch string = `{
        "op": "add",
        "path": "/spec/containers/%d/env/-",
        "value": {
            "name": "APPINSIGHTS_INSTRUMENTATIONKEY",
            "valueFrom" : {
                "secretKeyRef: {
                    "name": "%s",
                    "key": "APPINSIGHTS_INSTRUMENTATIONKEY"
                }
            }
        }
    }`

	// IKeyVarName is the well-known name for Application Insights insrumentation key environment variable
	IKeyVarName string = "APPINSIGHTS_INSTRUMENTATIONKEY"
)

// Data about a secret that contains Application Insights instrumentation key and other AppInsights configuration data.
type appInsightsSecret struct {
	Selector  metav1.LabelSelector
	Name      string
	Namespace string
}

type admitFunc func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

var (
	// CONSIDER It may be more robust to _also_ periodically load information about all secrets in the system and compare this
	// information with what we have cached in the aiSecrets slice

	aiSecrets     = make([]appInsightsSecret, 1)
	aiSecretsLock sync.RWMutex

	// AllowUnchanged is a standard response instructing Kubernetes to allow the object in its original form
	AllowUnchanged = v1beta1.AdmissionResponse{Allowed: true}

	decoder = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()
)

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
	if _, _, err := decoder.Decode(raw, nil, &secret); err != nil {
		glog.Error(err)
		return toAdmissionResponse(err)
	}

	operation := ar.Request.Operation
	if operation == v1beta1.Create {
		glog.V(2).Infof("Admitting new secret %s.%s", secret.Namespace, secret.Name)
		handleSecretCreation(secret)
	} else if operation == v1beta1.Delete {
		glog.V(2).Infof("Secret %s.%s is being deleted", secret.Namespace, secret.Name)
		handleSecretRemoval(secret)
	} else if operation == v1beta1.Update {
		glog.V(2).Infof("Secret %s.%s is being updated", secret.Namespace, secret.Name)

		oldSecret := corev1.Secret{}
		if _, _, err := decoder.Decode(ar.Request.OldObject.Raw, nil, &oldSecret); err != nil {
			glog.Error(err)
			return toAdmissionResponse(err)
		}

		handleSecretRemoval(oldSecret)
		handleSecretCreation(secret)
	}

	return &AllowUnchanged
}

func handleSecretRemoval(secret corev1.Secret) {
	if _, iKeyPresent := secret.Data[IKeyVarName]; !iKeyPresent {
		// Secret does not contain AppInsights instrumentation key--not relevant to us.
		return
	}

	// Taking a lock now ensures stable iteration over aiSecrets
	aiSecretsLock.Lock()
	defer aiSecretsLock.Unlock()

	newSecrets := make([]appInsightsSecret, len(aiSecrets))
	i := 0
	for _, aiSecret := range aiSecrets {
		if aiSecret.Name == secret.Name && aiSecret.Namespace == secret.Namespace {
			glog.V(2).Infof("Removing cached data for secret %s.%s", secret.Namespace, secret.Name)
			continue
		}

		newSecrets[i] = aiSecret
		i++
	}

	aiSecrets = newSecrets
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

	// Note: for the "update" operation ar.Request.Object is the "new" object vs. ar.Request.OldObject.
	// So whether it is a "create" operation, or "update" operation, ar.Request.Object is the right one to examine.
	raw := ar.Request.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := decoder.Decode(raw, nil, &pod); err != nil {
		glog.Error(err)
		return toAdmissionResponse(err)
	}
	glog.V(2).Infof("Admitting pod %s.%s ...", pod.Namespace, pod.Name)

	if ar.Request.Operation != v1beta1.Create && ar.Request.Operation != v1beta1.Update {
		glog.V(2).Infof("Operation on the pod %s is %s, allowing unchanged", pod.Name, ar.Request.Operation)
		return &AllowUnchanged
	}

	aiSecretsLock.RLock()
	defer aiSecretsLock.RUnlock()

	// Iterate aiSecrets slice backwards so that latest secrets are preferred
	for i := len(aiSecrets) - 1; i >= 0; i-- {
		secret := aiSecrets[i]
		selector, err := metav1.LabelSelectorAsSelector(&secret.Selector)
		if err != nil {
			glog.Warningf(
				"Unexpected error when trying to use secret %s.%s. One of the stored LabelSelectors could not be converted to a Selector. %s",
				secret.Namespace, secret.Name, err)
			continue
		}

		if secret.Namespace == pod.Namespace && selector.Matches(labels.Set(pod.Labels)) {
			glog.V(2).Infof("Using secret %s to inject AppInsights iKey into pod %s", secret.Name, pod.Name)
			return createPatchResponse(pod, i)
		}
	}

	glog.V(2).Infof("No matching secrets found for pod %s.%s, allowing unchanged", pod.Namespace, pod.Name)
	return &AllowUnchanged
}

func createPatchResponse(pod corev1.Pod, secretIndex int) *v1beta1.AdmissionResponse {
	response := v1beta1.AdmissionResponse{}
	response.Allowed = true
	patchList := ""

	for cIndex, container := range pod.Spec.Containers {

		// Make sure we do not patch if the AppInsights instrumentation key is already set on the pod
		iKeyVarExists := false
		for _, envVar := range container.Env {
			if envVar.Name == IKeyVarName {
				glog.V(2).Infof(
					"Container %s of pod %s already has an instrumentation key variable, skipping",
					container.Name, pod.Name)

				iKeyVarExists = true
				break
			}
		}
		if iKeyVarExists {
			continue
		}

		if len(patchList) > 0 {
			patchList += ",\n"
		}
		patchList += fmt.Sprintf(addIKeyVarPatch, cIndex, aiSecrets[secretIndex].Name)
	}

	if len(patchList) > 0 {
		patchStr := "[\n" + patchList + "\n]"
		glog.V(2).Infof("Patching request for pod %s is: %s", pod.Name, patchStr)
		response.Patch = []byte(patchStr)
		pt := v1beta1.PatchTypeJSONPatch
		response.PatchType = &pt
	} else {
		glog.V(2).Infof("None of the containers inside pod %s required patching to add instrumentation key variable", pod.Name)
	}

	return &response
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

	if glog.V(2) {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, body, "", "  "); err == nil {
			glog.V(2).Infof("Handling request: %s", string(prettyJSON.Bytes()))
		}
	}

	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := decoder.Decode(body, nil, &ar); err != nil {
		glog.Error(err)
		reviewResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		reviewResponse = admit(ar)
	}

	if glog.V(2) && len(reviewResponse.Patch) > 0 {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, reviewResponse.Patch, "", "  "); err == nil {
			glog.V(2).Infof("Sending patch response: %s", string(prettyJSON.Bytes()))
		}
	}

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

	clientset := getClient()
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: configTLS(certFile, keyFile, clientset),
	}

	glog.V(2).Info("Certificates loaded. Listening for requests...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		glog.Fatal(err)
	}
}
