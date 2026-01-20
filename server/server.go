// Copyright © 2018 Ricardo Aravena <raravena@branch.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server Main package implementation for the SSH server
package server

import (
	"fmt"
	glssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/testdata"
	"io"
	"os/exec"
	"regexp"
	"sync/atomic"
)

// Failure mode configuration
var (
	failMode   string
	failAfter  int32
	connectionCount int32
)

// StartServer Function that start the server using public keys for auth
func StartServer(publicKeys map[string]ssh.PublicKey, port int, failMode string, failAfter int32) {
	// Store fail mode globally for the session handler
	failMode = failMode
	connectionCount = 0
	if failAfter > 0 {
		atomic.StoreInt32(&failAfter, failAfter)
	}

	sshHandler := func(s glssh.Session) {
		connNum := atomic.AddInt32(&connectionCount, 1)

		// Check if we should fail at session creation
		if failMode == "session" {
			// Fail after specified number of connections
			currentFailAfter := atomic.LoadInt32(&failAfter)
			if currentFailAfter > 0 && connNum > currentFailAfter {
				s.Close()
				return
			}
		}

		// Handle scp
		rp := regexp.MustCompile("scp")
		if rp.MatchString(s.Command()[0]) {
			// Check if we should fail at pipe creation
			if failMode == "pipe" {
				currentFailAfter := atomic.LoadInt32(&failAfter)
				if currentFailAfter > 0 && connNum > currentFailAfter {
					return
				}
			}

			cmd := exec.Command(s.Command()[0], s.Command()[1:]...)

			// Check if we should fail at command start
			if failMode == "start" {
				currentFailAfter := atomic.LoadInt32(&failAfter)
				if currentFailAfter > 0 && connNum > currentFailAfter {
					return
				}
			}

			f, _ := cmd.StdinPipe()
			err := cmd.Start()
			if err != nil {
				panic(err)
			}
			io.Copy(f, s) // stdin
			f.Close()
			s.Close()
			err = cmd.Wait()
		}
	}

	publicKeyOption := glssh.PublicKeyAuth(func(ctx glssh.Context, key glssh.PublicKey) bool {
		for _, pubk := range publicKeys {
			if glssh.KeysEqual(key, pubk) {
				return true
			}
		}
		return false // use glssh.KeysEqual() to compare against known keys
	})

	fmt.Println("starting ssh server for scp tests on port", port, "...")
	if failMode != "" {
		fmt.Println("FAIL MODE:", failMode)
	}
	panic(glssh.ListenAndServe(":2224", sshHandler, publicKeyOption))
}

// Sshd Function that begins the server intantiation
func Sshd(port int, failMode string, failAfter int32) {
	var (
		testPrivateKeys map[string]interface{}
		testSigners     map[string]ssh.Signer
		testPublicKeys  map[string]ssh.PublicKey
		err             error
	)
	n := len(testdata.PEMBytes)
	testSigners = make(map[string]ssh.Signer, n)
	testPrivateKeys = make(map[string]interface{}, n)
	testPublicKeys = make(map[string]ssh.PublicKey, n)

	for t, k := range testdata.PEMBytes {
		testPrivateKeys[t], err = ssh.ParseRawPrivateKey(k)
		if err != nil {
			panic(fmt.Sprintf("Unable to parse test key %s: %v", t, err))
		}
		testSigners[t], err = ssh.NewSignerFromKey(testPrivateKeys[t])
		if err != nil {
			panic(fmt.Sprintf("Unable to create signer for test key %s: %v", t, err))
		}
		testPublicKeys[t] = testSigners[t].PublicKey()
	}
	StartServer(testPublicKeys, port, failMode, failAfter)
}
