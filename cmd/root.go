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

package cmd

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/raravena80/gotestsshd/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	port    int
)

// RootCmd Main root command
var RootCmd = &cobra.Command{
	Use:   "gotestsshd",
	Short: "Mini SSH Server for tests",
	Long: `This is a mini SSH Server for Tests
`,
	Run: func(cmd *cobra.Command, args []string) {
		server.Sshd(port)
	},
}

// Execute Main function that start the excution of the root command
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gotestsshd.yaml)")
	RootCmd.Flags().IntVarP(&port, "port", "p", 2224, "Port to bind server on")
	viper.BindPFlag("gotestsshd.port", RootCmd.Flags().Lookup("port"))
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".gotestsshd" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".gotestsshd")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
