// Copyright © 2017 Ricardo Aravena <raravena@branch.io>
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
package server

import (
	"fmt"
	glssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/testdata"
	"io"
	"os/exec"
	"regexp"
)

func StartServer(publicKeys map[string]ssh.PublicKey) {
	sshHandler := func(s glssh.Session) {
		authorizedKey := ssh.MarshalAuthorizedKey(s.PublicKey())
		io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
		s.Write(authorizedKey)
		io.WriteString(s, fmt.Sprintf("Command used %s:\n", s.Command()))
		// Handle scp
		rp := regexp.MustCompile("scp")
		if rp.MatchString(s.Command()[0]) {
			cmd := exec.Command(s.Command()[0], s.Command()[1:]...)
			f, _ := cmd.StdinPipe()
			err := cmd.Start()
			if err != nil {
				panic(err)
			}
			go func() {
				io.Copy(f, s) // stdin
			}()
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

	fmt.Println("starting ssh server for scp tests on port 2224...")
	panic(glssh.ListenAndServe(":2224", sshHandler, publicKeyOption))
}

func Sshd() {
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
	StartServer(testPublicKeys)
}
