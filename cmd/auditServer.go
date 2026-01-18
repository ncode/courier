/*
Copyright © 2024 Juliano Martinez <juliano@martinez.io>

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
package cmd

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/ncode/courier/pkg/auditserver"
	"github.com/ncode/courier/pkg/vault"
	"github.com/panjf2000/gnet/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// auditServerCmd represents the auditServer command
var auditServerCmd = &cobra.Command{
	Use:   "auditServer",
	Short: "Starts the audit server that listens for audit messages from Vault.",
	Long: `Starts the audit server that listens for audit messages from Vault.

The audit server listens for audit messages from Vault, based on the metadata of the path messages will be published to the appropriate channels.`,
	Run: func(cmd *cobra.Command, args []string) {
		addr := fmt.Sprintf("udp://%s", viper.GetString("vault.audit_address"))

		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
		workerConcurrency := viper.GetInt("worker.concurrency")
		workerQueueSize := viper.GetInt("worker.queue_size")

		sourceClient, err := vault.NewVaultClient(viper.GetString("vault.source.address"), vault.TokenAuth{Token: viper.GetString("vault.source.token")})
		if err != nil {
			log.Fatalf("Failed to create source vault client: %v", err)
		}

		destAddrs := splitAndTrim(viper.GetString("vault.destinations.addresses"))
		destTokens := splitAndTrim(viper.GetString("vault.destinations.tokens"))
		if len(destTokens) == 1 && len(destAddrs) > 1 {
			// Apply single token to all destinations if only one provided
			for len(destTokens) < len(destAddrs) {
				destTokens = append(destTokens, destTokens[0])
			}
		}
		if len(destAddrs) != len(destTokens) {
			log.Fatalf("destination addresses and tokens must have the same length")
		}

		var destConfigs []auditserver.DestinationConfig
		for i := range destAddrs {
			destConfigs = append(destConfigs, auditserver.DestinationConfig{
				Address: destAddrs[i],
				Token:   destTokens[i],
			})
		}

		syncer, err := auditserver.NewVaultSyncer(logger, sourceClient, destConfigs)
		if err != nil {
			log.Fatalf("Failed to create syncer: %v", err)
		}

		dispatcher := auditserver.NewDispatcher(logger, syncer.Handle, workerQueueSize, workerConcurrency)

		server := auditserver.New(logger, dispatcher)
		log.Fatal(gnet.Run(server, addr, gnet.WithMulticore(true)))
	},
}

func init() {
	rootCmd.AddCommand(auditServerCmd)

	auditServerCmd.PersistentFlags().Int("worker.concurrency", runtime.NumCPU(), "number of worker goroutines processing sync tasks")
	auditServerCmd.PersistentFlags().Int("worker.queue_size", 64, "queue size for pending sync tasks before dead-lettering")
	auditServerCmd.PersistentFlags().String("vault.destinations.addresses", "", "comma-separated list of destination Vault addresses")
	auditServerCmd.PersistentFlags().String("vault.destinations.tokens", "", "comma-separated list of destination Vault tokens (align with addresses)")
	viper.BindPFlag("worker.concurrency", auditServerCmd.PersistentFlags().Lookup("worker.concurrency"))
	viper.BindPFlag("worker.queue_size", auditServerCmd.PersistentFlags().Lookup("worker.queue_size"))
	viper.BindPFlag("vault.destinations.addresses", auditServerCmd.PersistentFlags().Lookup("vault.destinations.addresses"))
	viper.BindPFlag("vault.destinations.tokens", auditServerCmd.PersistentFlags().Lookup("vault.destinations.tokens"))
}

func splitAndTrim(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
