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
	"crypto/tls"
	"fmt"
	"github.com/ncode/courier/pkg/auditserver"
	"github.com/ncode/courier/pkg/broker"
	"github.com/panjf2000/gnet"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"log"

	"github.com/spf13/cobra"
)

// auditServerCmd represents the auditServer command
var auditServerCmd = &cobra.Command{
	Use:   "auditServer",
	Short: "Starts the audit server that listens for audit messages from Vault.",
	Long: `Starts the audit server that listens for audit messages from Vault.

The audit server listens for audit messages from Vault, based on the metadata of the path messages will be published to the appropriate channels.`,
	Run: func(cmd *cobra.Command, args []string) {
		addr := fmt.Sprintf("udp://%s", viper.GetString("vault.audit_address"))

		var tlsConfig *tls.Config
		var redisClient *redis.Client
		if viper.GetBool("publisher.tls") {
			cert, err := tls.LoadX509KeyPair(viper.GetString("publisher.server_cert"), viper.GetString("publisher.server_key"))
			if err != nil {
				log.Fatalf("Failed to load certificate: %v", err)
			}
			tlsConfig = &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
			}

			redisClient = redis.NewClient(&redis.Options{
				TLSConfig: tlsConfig,
			})
		}

		if viper.GetBool("publisher.server") {
			broker, err := broker.NewServer(viper.GetString("publisher.address"), nil)
			if err != nil {
				log.Fatalf("Failed to create publisher server: %v", err)
			}
			if viper.GetBool("publisher.tls") {
				go func() { log.Fatal(broker.ListenAndServeTLS(tlsConfig)) }()
			} else {
				go func() { log.Fatal(broker.ListenAndServe()) }()
			}
		}

		server := auditserver.New(nil, redisClient)
		log.Fatal(gnet.Serve(server, addr, gnet.WithMulticore(true)))
	},
}

func init() {
	rootCmd.AddCommand(auditServerCmd)

	auditServerCmd.PersistentFlags().Bool("publisher.server", true, "enables local publisher server")
	auditServerCmd.PersistentFlags().String("publisher.server_cert", "", "certificate file for publisher server")
	auditServerCmd.PersistentFlags().String("publisher.server_key", "", "key file for publisher server")
	auditServerCmd.PersistentFlags().Bool("publisher.tls", true, "publish messages via TLS")
	auditServerCmd.PersistentFlags().String("publisher.address", "127.0.0.1:6380", "A help for foo")
	viper.BindPFlag("publisher.server", auditServerCmd.PersistentFlags().Lookup("publisher.server"))
	viper.BindPFlag("publisher.server_cert", auditServerCmd.PersistentFlags().Lookup("publisher.server_cert"))
	viper.BindPFlag("publisher.server_key", auditServerCmd.PersistentFlags().Lookup("publisher.server_key"))
	viper.BindPFlag("publisher.tls", auditServerCmd.PersistentFlags().Lookup("publisher.tls"))
	viper.BindPFlag("publisher.address", auditServerCmd.PersistentFlags().Lookup("publisher.address"))
}
