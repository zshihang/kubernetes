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

package volume_test

import (
	"testing"

	gcli "github.com/heketi/heketi/client/api/go-client"
	quobyte "github.com/quobyte/api"
	storageos "github.com/storageos/go-api"
)

func TestFork_Heketi(t *testing.T) {
	// This will fail to compile if our patches to heketi are lost.
	opts := gcli.DefaultClientOptions()
	opts.DialContext = nil
}

func TestFork_Quobyte(t *testing.T) {
	// This will fail to compile if our patches to quobyte are lost.
	q := &quobyte.QuobyteClient{}
	_ = q.SetTransport
}

func TestFork_Storageos(t *testing.T) {
	// This will fail to compile if our patches to storageos are lost.
	s := &storageos.Client{}
	_ = s.SetDialContext
}
