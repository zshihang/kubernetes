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
	"sync/atomic"

	"k8s.io/apiserver/pkg/admission/plugin/webhook"
)

type wrappedSource struct {
	watcher                        *ManifestWatcher
	embedded                       Source
	webhookType                    WebhookType
	generation                     uint64
	lastObservedGenerationEmbedded uint64
	lastObservedGenerationManifest uint64
	hooks                          *atomic.Value
}

// ServerContext is currently just used to shutdown the admission manifest
// watchers gracefully in integration tests. This package variable is only used
// temporarily and will be dropped in favor of a server context
// plumbed through from NewWebhook().
var ServerContext = context.Background()

func (s *wrappedSource) Webhooks() []webhook.WebhookAccessor {
	if s.embedded == nil {
		return s.watcher.getWebhookAccessors()
	}
	// Hooks in embedded source (from API) and the hooks from the manifest file
	// change infrequently, however this method is called frequently, so
	// merging s.watcher.getWebhookAccessors() and s.embedded.Webhooks() on every
	// call is not efficient. Instead, we only merge if we either have a new
	// generation of hooks from the API or a new generation of hooks from the
	// manifest file.
	curManifestGen := s.watcher.generation()
	curEmbeddedGen := s.embedded.Generation()
	lastObservedGenerationEmbedded := atomic.LoadUint64(&s.lastObservedGenerationEmbedded)
	lastObservedGenerationManifest := atomic.LoadUint64(&s.lastObservedGenerationManifest)
	if curEmbeddedGen > lastObservedGenerationEmbedded ||
		curManifestGen > lastObservedGenerationManifest {
		atomic.AddUint64(&s.generation, 1)
		atomic.CompareAndSwapUint64(&s.lastObservedGenerationManifest, lastObservedGenerationManifest, curManifestGen)
		atomic.CompareAndSwapUint64(&s.lastObservedGenerationEmbedded, lastObservedGenerationEmbedded, curEmbeddedGen)

		var hooks []webhook.WebhookAccessor
		hooks = append(hooks, s.watcher.getWebhookAccessors()...)
		hooks = append(hooks, s.embedded.Webhooks()...)
		s.hooks.Store(hooks)
	}

	hooks := s.hooks.Load()
	if hooks == nil {
		return []webhook.WebhookAccessor{}
	}
	return hooks.([]webhook.WebhookAccessor)
}

func (s *wrappedSource) HasSynced() bool {
	if s.embedded != nil {
		return s.embedded.HasSynced()
	}
	return true
}

func (s *wrappedSource) WebhookType() WebhookType {
	return s.webhookType
}

func (s *wrappedSource) Generation() uint64 {
	return atomic.LoadUint64(&s.generation)
}

// NewWrappedSource returns a webhook Source that adds in webhooks from the
// specified ManifestWatcher to the specified Source.
func NewWrappedSource(embedded Source, m *ManifestWatcher) Source {
	return &wrappedSource{embedded: embedded, watcher: m, hooks: &atomic.Value{}, webhookType: embedded.WebhookType()}
}

type manifestHookWrapper struct {
	manifestFile string
	defaulter    WebhookDefaulter
	validator    WebhookValidator
	watcher      *ManifestWatcher
	ctx          context.Context
}

// NewManifestHookWrapper returns a new manifestHookWrapper which implements
// ManifestWebhookWrapper
func NewManifestHookWrapper(manifestFile string, d WebhookDefaulter, v WebhookValidator) ManifestWebhookWrapper {
	return &manifestHookWrapper{
		manifestFile: manifestFile,
		defaulter:    d,
		validator:    v,
		watcher:      NewManifestWatcher(manifestFile, d, v),
	}
}

func (m *manifestHookWrapper) Initialize(ctx context.Context, webhookType WebhookType) error {
	return m.watcher.Init(webhookType, ctx)
}

func (m *manifestHookWrapper) WrapHookSource(s Source) Source {
	return NewWrappedSource(s, m.watcher)
}
