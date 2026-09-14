package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/akash-network/provider/cmd/pircli"
)

func main() {
	root := &cobra.Command{
		Use:          "provider-services",
		Short:        "re-zerve provider sidecar (pir check/serve/stop)",
		SilenceUsage: true,
	}
	root.AddCommand(pircli.Command())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
