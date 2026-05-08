// Plugin entry point. Vault execs this binary, passes connection
// metadata via environment variables, and the SDK's
// plugin.ServeMultiplex wires Factory to the Vault host.
package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	argon2id "github.com/xiroko-inc/vault-plugin-secrets-argon2"
)

// version is overwritten at link time by the release pipeline
// (`-X main.version=<tag>`). Default is empty because Vault
// validates the reported plugin version as semver and rejects
// sentinel strings like "dev" — an un-stamped local build runs
// fine but reports no version through `vault plugin info`.
var version = ""

func main() {
	// Stamp the running version onto the backend so it shows up in
	// `vault plugin info` for operators. Must happen before
	// plugin.ServeMultiplex calls Factory.
	argon2id.PluginVersion = version

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatalf("parsing plugin flags: %v", err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: argon2id.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatalf("vault-plugin-secrets-argon2 server: %v", err)
	}
}
