/*
Copyright 2020 The Kubernetes Authors.

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

package generic

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/component-base/metrics/legacyregistry"

	"k8s.io/apiserver/pkg/admission/plugin/webhook"
)

var (
	validatingWebhookConfig = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: w1
webhooks:
- failurePolicy: Ignore
  name: w11.kube.io
  rules:
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - '*'
  sideEffects: None
  timeoutSeconds: 5
- failurePolicy: Fail
  name: w12.kube.io
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - namespaces
  sideEffects: None
  timeoutSeconds: 5
`
	validatingWebhookConfigList = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfigurationList
items:
- apiVersion: admissionregistration.k8s.io/v1
  kind: ValidatingWebhookConfiguration
  metadata:
    name: w2
  webhooks:
  - failurePolicy: Ignore
    name: w21.kube.io
    rules:
    - apiGroups:
      - '*'
      apiVersions:
      - '*'
      operations:
      - CREATE
      - UPDATE
      resources:
      - '*'
    sideEffects: None
    timeoutSeconds: 5
  - failurePolicy: Fail
    name: w22.kube.io
    rules:
    - apiGroups:
      - '*'
      apiVersions:
      - '*'
      operations:
      - CREATE
      - UPDATE
      resources:
      - '*'
    sideEffects: None
    timeoutSeconds: 5
`
	inValidValidatingWebhookConfigList = `
apiVersion: admissionregistration.k8s.io/v1
kind: someerror
items:
- apiVersion: admissionregistration.k8s.io/v1
  kind: ValidatingWebhookConfiguration
  metadata:
    name: w2
  webhooks:
  - failurePolicy: Ignore
    name: w21.kube.io
    rules:
    - apiGroups:
      - '*'
      apiVersions:
      - '*'
      operations:
      - CREATE
      - UPDATE
      resources:
      - '*'
    sideEffects: None
    timeoutSeconds: 5
  - failurePolicy: Fail
    name: w22.kube.io
    rules:
    - apiGroups:
      - '*'
      apiVersions:
      - '*'
      operations:
      - CREATE
      - UPDATE
      resources:
      - '*'
    sideEffects: None
    timeoutSeconds: 5
`
	mutatingWebhookConfig = `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: w1
webhooks:
- name: w31.kube.io
  rules:
  - operations: ["CREATE"]
    apiGroups: ["*"]
    apiVersions: ["*"]
    resources: ["*"]
    scope: "*"
  sideEffects: None
  timeoutSeconds: 5
`
	multiValidatingWebhookConfig = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: w1
webhooks:
- failurePolicy: Ignore
  name: w11.kube.io
  rules:
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - '*'
  sideEffects: None
  timeoutSeconds: 5
- failurePolicy: Fail
  name: w12.kube.io
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - namespaces
  sideEffects: None
  timeoutSeconds: 5
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: w2
webhooks:
- failurePolicy: Ignore
  name: w21.kube.io
  rules:
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - '*'
  sideEffects: None
  timeoutSeconds: 5
- failurePolicy: Fail
  name: w22.kube.io
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - namespaces
  sideEffects: None
  timeoutSeconds: 5
`
	validatingAndMutatingWebhookConfig = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: w1
webhooks:
- failurePolicy: Ignore
  name: w11.kube.io
  rules:
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - '*'
  sideEffects: None
  timeoutSeconds: 5
- failurePolicy: Fail
  name: w12.kube.io
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - namespaces
  sideEffects: None
  timeoutSeconds: 5
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: w2
webhooks:
- failurePolicy: Ignore
  name: w21.kube.io
  rules:
  - apiGroups:
    - '*'
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - '*'
  sideEffects: None
  timeoutSeconds: 5
- failurePolicy: Fail
  name: w22.kube.io
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - '*'
    operations:
    - CREATE
    - UPDATE
    resources:
    - namespaces
  sideEffects: None
  timeoutSeconds: 5
`
	listOfValidatingWebhookConfig = `
apiVersion: meta.k8s.io/v1
kind: List
items:
- apiVersion: admissionregistration.k8s.io/v1
  kind: ValidatingWebhookConfiguration
  metadata:
    name: w1
  webhooks:
  - failurePolicy: Ignore
    name: w11.kube.io
    rules:
    - apiGroups:
      - '*'
      apiVersions:
      - '*'
      operations:
      - CREATE
      - UPDATE
      resources:
      - '*'
    sideEffects: None
    timeoutSeconds: 5
  - failurePolicy: Fail
    name: w12.kube.io
    rules:
    - apiGroups:
      - '*'
      apiVersions:
      - '*'
      operations:
      - CREATE
      - UPDATE
      resources:
      - '*'
    sideEffects: None
    timeoutSeconds: 5
`
	webhook1 = webhook.NewMutatingWebhookAccessor("uid", "w4", &v1.MutatingWebhook{
		Name: "w41.kube.io",
		Rules: []v1.RuleWithOperations{{
			Operations: []v1.OperationType{v1.Create},
		}},
	})
)

func Test_ManifestWebhookConfig(t *testing.T) {
	testCases := []struct {
		name             string
		dynamicWebhooks  []webhook.WebhookAccessor
		manifestConfig   string
		WebhookType      WebhookType
		expectedWebhooks sets.String
	}{
		{
			"no dynamic webhooks; validating webhook configuration list",
			nil,
			validatingWebhookConfigList,
			ValidatingWebhook,
			sets.NewString("w21.kube.io", "w22.kube.io"),
		},
		{
			"no dynamic webhooks; validating webhook configuration",
			nil,
			validatingWebhookConfig,
			ValidatingWebhook,
			sets.NewString("w11.kube.io", "w12.kube.io"),
		},
		{
			"no dynamic webhooks; validating webhook configuration",
			nil,
			validatingWebhookConfig,
			ValidatingWebhook,
			sets.NewString("w11.kube.io", "w12.kube.io"),
		},
		{
			"no dynamic webhooks; mutating webhook configuration",
			nil,
			mutatingWebhookConfig,
			MutatingWebhook,
			sets.NewString("w31.kube.io"),
		},
		{
			"no dynamic webhooks; multi validating webhook configuration",
			nil,
			multiValidatingWebhookConfig,
			ValidatingWebhook,
			sets.NewString("w11.kube.io", "w12.kube.io", "w21.kube.io", "w22.kube.io"),
		},
		{
			"one dynamic webhooks; mutating webhook configuration",
			[]webhook.WebhookAccessor{webhook1},
			mutatingWebhookConfig,
			MutatingWebhook,
			sets.NewString("w31.kube.io", "w41.kube.io"),
		},
		{
			"no dynamic webhooks; list of validating webhook configuration",
			nil,
			listOfValidatingWebhookConfig,
			ValidatingWebhook,
			sets.NewString("w11.kube.io", "w12.kube.io"),
		},
		{
			"no dynamic webhooks; validating and mutating webhook configuration",
			nil,
			validatingAndMutatingWebhookConfig,
			MutatingWebhook,
			sets.NewString("w21.kube.io", "w22.kube.io"),
		},
	}

	tempFile, err := ioutil.TempFile("", "")
	assert.NoError(t, err)
	tempFile.Close()
	defer os.Remove(tempFile.Name())
	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err = ioutil.WriteFile(tempFile.Name(), []byte(tc.manifestConfig), os.FileMode(0755))
			assert.NoError(t, err)

			wrapper := NewManifestHookWrapper(tempFile.Name(), nil, nil)
			err := wrapper.Initialize(ctx, tc.WebhookType)
			assert.NoError(t, err)
			hookSource := wrapper.WrapHookSource(&testSource{webhooks: tc.dynamicWebhooks})
			got := set(hookSource.Webhooks())
			if !got.Equal(tc.expectedWebhooks) {
				assert.Failf(t, "Mismatched hooks", "Expected hooks: %v, got: %v", tc.expectedWebhooks, got)
			}
		})
	}
}

func set(hooks []webhook.WebhookAccessor) sets.String {
	set := sets.String{}
	for _, hook := range hooks {
		set.Insert(hook.GetName())
	}
	return set
}

func Test_ManifestConfigWatch(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "")
	assert.NoError(t, err)
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	err = ioutil.WriteFile(tempFile.Name(), []byte(validatingWebhookConfig), os.FileMode(0755))
	assert.NoError(t, err)

	wrapper := NewManifestHookWrapper(tempFile.Name(), nil, nil)
	ctx, cancel := context.WithCancel(context.TODO())
	err = wrapper.Initialize(ctx, ValidatingWebhook)
	assert.NoError(t, err)
	hookSource := wrapper.WrapHookSource(&testSource{webhooks: nil})

	expectedHooks := sets.NewString("w11.kube.io", "w12.kube.io")
	got := set(hookSource.Webhooks())
	if !got.Equal(expectedHooks) {
		assert.Failf(t, "Mismatched hooks", "Expected hooks: %v, got: %v", expectedHooks, got)
	}

	// Update file
	err = ioutil.WriteFile(tempFile.Name(), []byte(validatingWebhookConfigList), os.FileMode(0755))
	assert.NoError(t, err)

	expectedHooks = sets.NewString("w21.kube.io", "w22.kube.io")
	//wait for reload
	time.Sleep(time.Second)
	got = set(hookSource.Webhooks())
	if !got.Equal(expectedHooks) {
		assert.Failf(t, "Mismatched hooks", "Expected hooks: %v, got: %v", expectedHooks, got)
	}

	// cancel context and close watcher; expect the older webhooks
	cancel()

	time.Sleep(time.Second)

	// Load new config; valid but the webhooks not reloaded; asserting that the
	// watchers are closed.
	err = ioutil.WriteFile(tempFile.Name(), []byte(validatingWebhookConfig), os.FileMode(0755))
	assert.NoError(t, err)
	//wait for reload
	time.Sleep(time.Second)
	got = set(hookSource.Webhooks())
	if !got.Equal(expectedHooks) {
		assert.Failf(t, "Mismatched hooks", "Expected hooks: %v, got: %v", expectedHooks, got)
	}
}

func Test_ManifestWatchError(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "")
	assert.NoError(t, err)
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	err = ioutil.WriteFile(tempFile.Name(), []byte(validatingWebhookConfig), os.FileMode(0755))
	assert.NoError(t, err)

	wrapper := NewManifestHookWrapper(tempFile.Name(), nil, nil)
	ctx := context.Background()
	err = wrapper.Initialize(ctx, ValidatingWebhook)
	assert.NoError(t, err)
	hookSource := wrapper.WrapHookSource(&testSource{webhooks: nil})

	expectedHooks := sets.NewString("w11.kube.io", "w12.kube.io")
	got := set(hookSource.Webhooks())
	if !got.Equal(expectedHooks) {
		assert.Failf(t, "Mismatched hooks", "Expected hooks: %v, got: %v", expectedHooks, got)
	}

	// Update file
	err = ioutil.WriteFile(tempFile.Name(), []byte(inValidValidatingWebhookConfigList), os.FileMode(0755))
	assert.NoError(t, err)

	//wait for reload
	time.Sleep(time.Second)
	expectGaugeValue(t, "apiserver_admission_gke_webhook_manifest_error", 1)

	// Update file again
	err = ioutil.WriteFile(tempFile.Name(), []byte(validatingWebhookConfigList), os.FileMode(0755))
	assert.NoError(t, err)

	//wait for reload
	time.Sleep(time.Second)
	expectGaugeValue(t, "apiserver_admission_gke_webhook_manifest_error", 0)
}

func expectGaugeValue(t *testing.T, name string, wantCount int) {
	metrics, err := legacyregistry.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %s", err)
	}

	counterSum := 0
	val := 0
	for _, mf := range metrics {
		if mf.GetName() != name {
			continue // Ignore other metrics.
		}
		for _, metric := range mf.GetMetric() {
			val = int(metric.GetGauge().GetValue())
		}
	}
	if wantCount != val {
		t.Errorf("Wanted value %d, got %d for metric %s", wantCount, counterSum, name)
	}
}

type testSource struct {
	webhooks    []webhook.WebhookAccessor
	webhookType WebhookType
	generation  uint64
}

func (t *testSource) Webhooks() []webhook.WebhookAccessor {
	t.generation++
	return t.webhooks
}

func (t *testSource) HasSynced() bool {
	return true
}

func (t *testSource) WebhookType() WebhookType {
	return t.webhookType
}

func (t *testSource) Generation() uint64 {
	return t.generation
}
