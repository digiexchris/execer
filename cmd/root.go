// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
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
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"bufio"

	"github.com/prometheus/common/log"
	"github.com/spf13/cobra"
	"syscall"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/user"
	"time"
)

var cmds []string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "execer",
	Short: "executes your programs",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		ctx, cancel := context.WithCancel(ctx)
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		defer func() {
			signal.Stop(c)
			cancel()
		}()

		go func() {
			select {
			case <-c:
				cancel()
			case <-ctx.Done():
			}
		}()

		for _, a := range cmds {
			cmd := exec.CommandContext(ctx, a)
			var out bytes.Buffer
			cmd.Stdout = &out
			err := cmd.Run()
			if err != nil {
				log.Errorln(err)
				cancel()
				break
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				log.Errorln(err)
				cancel()
				break
			}
			scanner := bufio.NewScanner(stdout)
			go func() {
				for scanner.Scan() {
					select {
					case <-ctx.Done():
						break
					default:
						fmt.Println(scanner.Text())
					}
				}
			}()
			if err := scanner.Err(); err != nil {
				fmt.Fprintln(os.Stderr, "reading standard input:", err)
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	var user, group, logPrefix string
	rootCmd.PersistentFlags().StringVarP(&user, "user", "u", "root", "")
	rootCmd.PersistentFlags().StringVarP(&group, "group", "g", "root", "")
	rootCmd.PersistentFlags().StringVarP(&logPrefix, "prefix", "p", "app", "")
	rootCmd.PersistentFlags().StringArrayVarP(&cmds, "cmds", "c", []string{}, "")

	setupUser(fmt.Sprintf("%s:%s", user, group))
}

func setupUser(u string) error {
	defaultExecUser := user.ExecUser{
		Uid:  syscall.Getuid(),
		Gid:  syscall.Getgid(),
		Home: "/",
	}
	passwdPath, err := user.GetPasswdPath()
	if err != nil {
		return err
	}
	groupPath, err := user.GetGroupPath()
	if err != nil {
		return err
	}
	execUser, err := user.GetExecUserPath(u, &defaultExecUser, passwdPath, groupPath)
	if err != nil {
		return err
	}
	if err := syscall.Setgroups(execUser.Sgids); err != nil {
		return err
	}
	if err := system.Setgid(execUser.Gid); err != nil {
		return err
	}
	if err := system.Setuid(execUser.Uid); err != nil {
		return err
	}
	// if we didn't get HOME already, set it based on the user's HOME
	if envHome := os.Getenv("HOME"); envHome == "" {
		if err := os.Setenv("HOME", execUser.Home); err != nil {
			return err
		}
	}
	return nil
}