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
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Client struct {
	instance *ssh.Client
}

func (c *Client) Instance() *ssh.Client {
	return c.instance
}

// NewClient Initialize SSH client instance, with host, username and password,
// host contains ip and port, for example: example.com:22, 10.10.10.10:22.
func NewClient(host string, username string, password string) (*Client, error) {
	var auths []ssh.AuthMethod

	parse, err := fixedHost(host)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse host %s to URL", host)
	}

	// Get host key.
	hostKey, err := getHostKey(parse.Hostname())
	if err != nil {
		return nil, err
	}

	// Try to use $SSH_AUTH_SOCK which contains the path of the unix file
	// socket that the sshd agent uses for communication with other processes.
	if uc, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(uc).Signers))
	}

	// Use password authentication if provided.
	if password != "" {
		auths = append(auths, ssh.Password(password))
	}

	// Initialize instance configuration
	config := ssh.ClientConfig{
		User: username,
		Auth: auths,
		// Uncomment to ignore host key check
		// HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	// Connect to server.
	client, err := ssh.Dial("tcp", parse.Host, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to connecto to [%s]: %v\n", parse.Host, err)
	}

	return &Client{instance: client}, nil
}

// Get valid host.
func fixedHost(host string) (*url.URL, error) {
	if !strings.Contains(host, "://") {
		host = fmt.Sprintf("tcp://%s", host)
	}

	parse, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	return parse, nil
}

// Get host key from local known hosts
func getHostKey(host string) (ssh.PublicKey, error) {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("unable to read known_hosts file: %v\n", err)
	}
	defer file.Close()

	var scanner = bufio.NewScanner(file)
	var hostKey ssh.PublicKey

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, fmt.Errorf("Error parsing %q: %v\n", fields[2], err)
			}
			break
		}
	}

	if hostKey == nil {
		return nil, fmt.Errorf("no hostkey found for %s", host)
	}

	return hostKey, nil
}
