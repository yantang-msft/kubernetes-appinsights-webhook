// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under MIT License.

package main

import (
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Data stored in the applicationinsights-info annotation on a secret that is used for Application Insights data injection
type appInsightsAnnotation struct {
	Selectors []metav1.LabelSelector
}

// Data the webhook tracks about a secret that is used for Application Insights data injection
type appInsightsSecret struct {
	Annotation        appInsightsAnnotation
	Name              string
	Namespace         string
	CreationTimestamp metav1.Time
}

type byCreationTimestamp []appInsightsSecret

func (ss byCreationTimestamp) Len() int      { return len(ss) }
func (ss byCreationTimestamp) Swap(i, j int) { ss[i], ss[j] = ss[j], ss[i] }
func (ss byCreationTimestamp) Less(i, j int) bool {
	cti, ctj := ss[i].CreationTimestamp, ss[j].CreationTimestamp
	if cti.IsZero() && ctj.IsZero() {
		return ss[i].Name < ss[j].Name // Arbitrary, but ensures that sort order is well-defined
	}
	// Secrets with unknown creation time are considered "old"
	if cti.IsZero() {
		return true
	}
	if ctj.IsZero() {
		return false
	}
	return cti.Time.Before(ctj.Time)
}

func toAppInsightsSecretInfo(secret corev1.Secret) (*appInsightsSecret, error) {
	aiAnnotation, aiAnnotationPresent := secret.Annotations[AppInsightsInfoAnnotation]
	if !aiAnnotationPresent {
		glog.V(2).Infof("Secret %s does not have Application Insights annotation", secret.Name)
		return nil, nil
	}

	glog.V(2).Infof("Adding %s to list of secrets with AppInsights information", secret.Name)

	ais := appInsightsSecret{}
	ais.Name = secret.Name
	ais.Namespace = secret.Namespace
	ais.CreationTimestamp = secret.CreationTimestamp
	err := yaml.Unmarshal([]byte(aiAnnotation), &ais.Annotation)
	if err != nil {
		glog.Warningf("Could not parse Application Insights annotation on secret %s: %v", secret.Name, err)
		return nil, err
	}

	if len(ais.Annotation.Selectors) == 0 {
		err = fmt.Errorf("Application Insights annotation on secret %s has no selectors. The annotation will have no effect", secret.Name)
		glog.Warning(err)
		return nil, err
	}

	return &ais, nil
}
