package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Bobsans/DarkVault/cli/config"
	client "github.com/Bobsans/DarkVault/clients/go"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Explicit flags override environment variables; the saved file supplies the remaining defaults.
func resolveConfiguration(cmd *cobra.Command, filename string) (config.Settings, error) {
	settings, err := config.Load(filename)
	if err != nil {
		return settings, err
	}
	value := func(flag, env, fallback string) string {
		if cmd.Flags().Changed(flag) {
			v, _ := cmd.Flags().GetString(flag)
			return v
		}
		if v := os.Getenv(env); v != "" {
			return v
		}
		return fallback
	}
	settings.Server = value("server", "DARKVAULT_SERVER", settings.Server)
	settings.Server, err = client.NormalizeServer(settings.Server)
	if err != nil {
		return settings, errors.New("set a valid HTTPS server with --server, DARKVAULT_SERVER or config set server")
	}
	if err = settings.Set("timeout", value("timeout", "DARKVAULT_TIMEOUT", settings.Timeout)); err != nil {
		return settings, err
	}
	pageSize := os.Getenv("DARKVAULT_PAGE_SIZE")
	if pageSize == "" {
		pageSize = strconv.Itoa(settings.PageSize)
	}
	if cmd.Flags().Lookup("limit") != nil && cmd.Flags().Changed("limit") {
		n, _ := cmd.Flags().GetInt("limit")
		pageSize = strconv.Itoa(n)
	}
	if err = settings.Set("page-size", pageSize); err != nil {
		return settings, err
	}
	var tokenFile string
	switch {
	case cmd.Flags().Changed("token"):
		settings.Token, _ = cmd.Flags().GetString("token")
		err = client.ValidateToken(settings.Token)
	case cmd.Flags().Changed("token-file"):
		tokenFile, _ = cmd.Flags().GetString("token-file")
		if tokenFile == "" {
			err = errors.New("token file path is empty")
		}
	case os.Getenv("DARKVAULT_TOKEN_FILE") != "":
		tokenFile = os.Getenv("DARKVAULT_TOKEN_FILE")
	case os.Getenv("DARKVAULT_TOKEN") != "":
		settings.Token = os.Getenv("DARKVAULT_TOKEN")
	}
	if err != nil {
		return settings, err
	}
	if tokenFile != "" {
		file, e := os.Open(tokenFile)
		if e != nil {
			return settings, errors.New("cannot read token file")
		}
		defer file.Close()
		data, e := io.ReadAll(io.LimitReader(file, 4097))
		if e != nil || len(data) > 4096 {
			return settings, errors.New("cannot read token file (maximum 4 KiB)")
		}
		settings.Token = strings.TrimRight(string(data), "\r\n")
		if err = client.ValidateToken(settings.Token); err != nil {
			return settings, err
		}
	}
	return settings, settings.Validate()
}
func connect(cmd *cobra.Command, settings config.Settings) (*client.Client, error) {
	if settings.Token == "" {
		fmt.Fprint(cmd.ErrOrStderr(), "Token: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return nil, errors.New("provide a token using config set token, --token-file or DARKVAULT_TOKEN")
		}
		settings.Token = string(data)
	}
	c, err := client.New(settings.Server, settings.Token)
	if err != nil {
		return nil, err
	}
	c.HTTP.Timeout, _ = config.ParseTimeout(settings.Timeout)
	return c, nil
}

func configurationCommand(path func() (string, error)) *cobra.Command {
	group := &cobra.Command{Use: "config", Short: "Manage saved defaults (tokens are redacted in output)"}
	var stdin bool
	set := &cobra.Command{Use: "set <key> [value]", Short: "Save server, token, timeout or page-size", Args: cobra.RangeArgs(1, 2), RunE: func(cmd *cobra.Command, args []string) error {
		filename, err := path()
		if err != nil {
			return err
		}
		settings, err := config.Load(filename)
		if err != nil {
			return err
		}
		var value string
		if args[0] == "token" && len(args) == 1 {
			var data []byte
			if stdin {
				data, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 4097))
			} else {
				fmt.Fprint(cmd.ErrOrStderr(), "Token: ")
				data, err = term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(cmd.ErrOrStderr())
			}
			if err != nil || len(data) > 4096 {
				return errors.New("cannot read token; use --stdin for redirected input")
			}
			value = strings.TrimRight(string(data), "\r\n")
		} else {
			if len(args) != 2 || stdin {
				return errors.New("provide a value, or use config set token --stdin")
			}
			value = args[1]
		}
		if err = settings.Set(args[0], value); err != nil {
			return err
		}
		return config.Save(filename, settings)
	}}
	set.Flags().BoolVar(&stdin, "stdin", false, "Read token from stdin instead of a command argument")
	group.AddCommand(set)
	group.AddCommand(&cobra.Command{Use: "get <key>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		filename, err := path()
		if err != nil {
			return err
		}
		settings, err := config.Load(filename)
		if err != nil {
			return err
		}
		value, err := settings.Get(args[0])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), value)
		return err
	}})
	group.AddCommand(&cobra.Command{Use: "unset <key>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		filename, err := path()
		if err != nil {
			return err
		}
		settings, err := config.Load(filename)
		if err != nil {
			return err
		}
		if err = settings.Unset(args[0]); err != nil {
			return err
		}
		return config.Save(filename, settings)
	}})
	group.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		filename, err := path()
		if err != nil {
			return err
		}
		settings, err := config.Load(filename)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(settings.Redacted())
	}})
	group.AddCommand(&cobra.Command{Use: "path", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		filename, err := path()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), filename)
		return err
	}})
	return group
}
