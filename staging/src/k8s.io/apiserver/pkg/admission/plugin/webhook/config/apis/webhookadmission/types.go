/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhookadmission

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WebhookAdmission provides configuration for the webhook admission controller.
type WebhookAdmission struct {
	metav1.TypeMeta

	// KubeConfigFile is the path to the kubeconfig file.
	KubeConfigFile string

	// ManifestFile is the path to the manifest file containing
	// webhook configurations. Manifest file can contain any combination of
	// * `admissionregistration.k8s.io/v1.ValidatingWebhookConfigurationList`
	// * `admissionregistration.k8s.io/v1.MutatingWebhookConfigurationList`
	// * v1.List with items of admissionregistration.k8s.io/v1.ValidatingWebhookConfiguration
	// * v1.List  with items of admissionregistration.k8s.io/v1.MutatingWebhookConfiguration.
	ManifestFile string
}
