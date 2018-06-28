// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under MIT License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	patch1 string = `[
         { "op": "add", "path": "/data/mutation-stage-1", "value": "yes" }
     ]`
	patch2 string = `[
         { "op": "add", "path": "/data/mutation-stage-2", "value": "yes" }
     ]`
	addInitContainerPatch string = `[
		 {"op":"add","path":"/spec/initContainers","value":[{"image":"webhook-added-image","name":"webhook-added-init-container","resources":{}}]}
	]`
)

// Config contains the server (the webhook) cert and key.
type Config struct {
	CertFile string
	KeyFile  string
}

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
	glog.V(2).Info("admitting secrets")

	secretResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	if ar.Request.Resource != secretResource {
		err := fmt.Errorf("expect resource to be %s", secretResource)
		glog.Error(err)
		return toAdmissionResponse(err)
	}

	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	// TODO the following is sample code, irrelevant to what we really want to do
	// Implement the real thing with secrets

	/*
		raw := ar.Request.Object.Raw
		pod := corev1.Pod{}
		deserializer := codecs.UniversalDeserializer()
		if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
			glog.Error(err)
			return toAdmissionResponse(err)
		}


		var msg string
		if v, ok := pod.Labels["webhook-e2e-test"]; ok {
			if v == "webhook-disallow" {
				reviewResponse.Allowed = false
				msg = msg + "the pod contains unwanted label; "
			}
			if v == "wait-forever" {
				reviewResponse.Allowed = false
				msg = msg + "the pod response should not be sent; "
				<-make(chan int) // Sleep forever - no one sends to this channel
			}
		}
		for _, container := range pod.Spec.Containers {
			if strings.Contains(container.Name, "webhook-disallow") {
				reviewResponse.Allowed = false
				msg = msg + "the pod contains unwanted container name; "
			}
		}
		if !reviewResponse.Allowed {
			reviewResponse.Result = &metav1.Status{Message: strings.TrimSpace(msg)}
		}
	*/
	return &reviewResponse
}

func mutatePods(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {

	// TODO: implement
	/*
		glog.V(2).Info("mutating pods")
		podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
		if ar.Request.Resource != podResource {
			glog.Errorf("expect resource to be %s", podResource)
			return nil
		}

		raw := ar.Request.Object.Raw
		pod := corev1.Pod{}
		deserializer := codecs.UniversalDeserializer()
		if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
			glog.Error(err)
			return toAdmissionResponse(err)
		}
		reviewResponse := v1beta1.AdmissionResponse{}
		reviewResponse.Allowed = true
		if pod.Name == "webhook-to-be-mutated" {
			reviewResponse.Patch = []byte(addInitContainerPatch)
			pt := v1beta1.PatchTypeJSONPatch
			reviewResponse.PatchType = &pt
		}
		return &reviewResponse
	*/
}

type admitFunc func(v1beta1.AdmissionReview) *v1beta1.AdmissionResponse

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

	glog.V(2).Info(fmt.Sprintf("handling request: %v", body))
	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Error(err)
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = admit(ar)
	}
	glog.V(2).Info(fmt.Sprintf("sending response: %v", reviewResponse))

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
