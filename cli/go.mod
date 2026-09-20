module github.com/Bobsans/DarkVault/cli

go 1.26.0

require (
	github.com/Bobsans/DarkVault/clients/go v0.0.0
	github.com/spf13/cobra v1.10.1
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.37.0
)

replace github.com/Bobsans/DarkVault/clients/go => ../clients/go

require (
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
)
