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
// (`-X main.version=<tag>`). Default keeps local builds runnable
// without the ldflag.
var version = "dev"

func main() {
	_ = version // referenced by goreleaser ldflags; quiet the unused-var lint
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
