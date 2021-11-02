// Copyright 2021 helloshaohua <wu.shaohua@foxmail.com>;
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sshclient

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	host := os.Getenv("DESTINATION_SSH_HOST")         // example: 10.10.0.0:22
	username := os.Getenv("DESTINATION_SSH_USERNAME") // example: hello_world
	password := os.Getenv("DESTINATION_SSH_PASSWORD") // example: hello_world
	client, err := NewClient(host, username, password)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	defer client.Instance().Close()
}
