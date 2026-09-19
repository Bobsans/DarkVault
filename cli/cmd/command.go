package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/Bobsans/DarkVault/cli/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func Execute() int {
	if e := Command().Execute(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		var exit *exec.ExitError
		if errors.As(e, &exit) {
			return exit.ExitCode()
		}
		return 1
	}
	return 0
}
func Command() *cobra.Command {
	var configFile string
	root := &cobra.Command{Use: "darkvault", Short: "Encrypted secrets and scoped buckets", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().String("server", "", "HTTPS server origin (overrides environment and config)")
	root.PersistentFlags().String("token", "", "Access token (prefer --token-file or saved config for sensitive values)")
	root.PersistentFlags().String("token-file", "", "Private token file (overrides environment and config)")
	root.PersistentFlags().String("timeout", "", "Overall request timeout, 1s to 30s")
	root.PersistentFlags().StringVar(&configFile, "config", "", "Configuration file (default: user config directory)")
	root.MarkFlagsMutuallyExclusive("token", "token-file")
	path := func() (string, error) {
		if root.PersistentFlags().Changed("config") && configFile == "" {
			return "", errors.New("configuration file path is empty")
		}
		return config.Path(configFile)
	}
	root.AddCommand(configurationCommand(path))
	for _, kind := range []string{"bucket", "secret", "token"} {
		group := &cobra.Command{Use: kind}
		root.AddCommand(group)
		operations := []string{"add", "get", "list", "read", "update", "delete"}
		if kind == "secret" {
			operations = []string{"add", "get", "list", "update", "set", "delete"}
		}
		if kind == "token" {
			operations = []string{"info"}
		}
		for _, verb := range operations {
			kind, verb := kind, verb
			var revision int64
			var recursive, stdin bool
			var description, cursor, format string
			var limit int
			use := verb
			count := 0
			if kind == "bucket" && verb != "list" {
				use += " <bucket>"
				count = 1
			}
			if kind == "secret" {
				use += " <bucket>"
				count = 1
				if verb != "list" {
					use += " <key>"
					count = 2
				}
			}
			cmd := &cobra.Command{Use: use, Args: cobra.ExactArgs(count)}
			cmd.Flags().Int64Var(&revision, "revision", 0, "Expected revision (0 means absent)")
			cmd.Flags().BoolVar(&recursive, "recursive", false, "Delete a non-empty bucket")
			cmd.Flags().BoolVar(&stdin, "stdin", false, "Read value from stdin")
			cmd.Flags().StringVar(&description, "description", "", "Bucket description")
			cmd.Flags().StringVar(&cursor, "cursor", "", "Opaque listing cursor")
			cmd.Flags().IntVar(&limit, "limit", 100, "Page size (overrides config page-size)")
			cmd.Flags().StringVar(&format, "format", "json", "Output format (json)")
			cmd.RunE = func(cmd *cobra.Command, args []string) error {
				if format != "json" {
					return errors.New("only json format is supported")
				}
				filename, e := path()
				if e != nil {
					return e
				}
				settings, e := resolveConfiguration(cmd, filename)
				if e != nil {
					return e
				}
				c, e := connect(cmd, settings)
				if e != nil {
					return e
				}
				p := map[string]any{}
				op := verb
				switch verb {
				case "add":
					op = "create"
				case "get":
					if kind == "secret" {
						op = "read"
					}
				}
				if len(args) > 0 {
					if kind == "bucket" && verb == "add" {
						p["name"] = args[0]
					} else {
						p["bucket"] = args[0]
					}
				}
				if len(args) > 1 {
					p["key"] = args[1]
				}
				if verb == "list" {
					limit = settings.PageSize
					p["limit"] = limit
					if cursor != "" {
						p["cursor"] = cursor
					}
				}
				if kind == "bucket" && (verb == "add" || verb == "update") {
					p["description"] = description
				}
				if verb == "update" || verb == "set" || verb == "delete" {
					if verb != "set" && !cmd.Flags().Changed("revision") {
						return errors.New("--revision is required")
					}
					p["expectedRevision"] = revision
				}
				if kind == "bucket" && verb == "delete" {
					p["recursive"] = recursive
				}
				if kind == "secret" && (verb == "add" || verb == "update" || verb == "set") {
					var b []byte
					if stdin {
						b, e = io.ReadAll(io.LimitReader(os.Stdin, 65537))
					} else {
						fmt.Fprint(os.Stderr, "Value: ")
						b, e = term.ReadPassword(int(os.Stdin.Fd()))
						fmt.Fprintln(os.Stderr)
					}
					if e != nil {
						return e
					}
					if len(b) > 65536 || !utf8.Valid(b) {
						return errors.New("value must be UTF-8 and at most 64 KiB")
					}
					p["value"] = string(b)
				}
				result, e := c.Execute(cmd.Context(), kind+"."+op, p)
				if e != nil {
					return e
				}
				if kind == "secret" && verb == "get" {
					var s struct {
						Value string `json:"value"`
					}
					if e = json.Unmarshal(result, &s); e != nil {
						return e
					}
					_, e = fmt.Fprint(cmd.OutOrStdout(), s.Value)
					return e
				}
				_, e = fmt.Fprintln(cmd.OutOrStdout(), string(result))
				return e
			}
			group.AddCommand(cmd)
		}
	}
	var bucket string
	var aspnet, overwrite bool
	run := &cobra.Command{Use: "exec --bucket <name> -- <program> [args...]", Args: cobra.MinimumNArgs(1)}
	run.Flags().StringVar(&bucket, "bucket", "", "Bucket name")
	run.Flags().BoolVar(&aspnet, "aspnet-keys", false, "Map : to __ in environment names")
	run.Flags().BoolVar(&overwrite, "overwrite-env", false, "Allow replacing inherited variables")
	run.RunE = func(cmd *cobra.Command, args []string) error {
		if bucket == "" {
			return errors.New("--bucket is required")
		}
		filename, e := path()
		if e != nil {
			return e
		}
		settings, e := resolveConfiguration(cmd, filename)
		if e != nil {
			return e
		}
		c, e := connect(cmd, settings)
		if e != nil {
			return e
		}
		values, e := c.ReadBucket(cmd.Context(), bucket)
		if e != nil {
			return e
		}
		env, e := Environment(os.Environ(), values, aspnet, overwrite)
		if e != nil {
			return e
		}
		child := exec.CommandContext(cmd.Context(), args[0], args[1:]...)
		child.Env = env
		child.Stdin = os.Stdin
		child.Stdout = cmd.OutOrStdout()
		child.Stderr = cmd.ErrOrStderr()
		return child.Run()
	}
	root.AddCommand(run)
	return root
}
func Environment(inherited []string, values map[string]string, aspnet, overwrite bool) ([]string, error) {
	env := map[string]string{}
	normalize := func(s string) string {
		if runtime.GOOS == "windows" {
			return strings.ToUpper(s)
		}
		return s
	}
	for _, s := range inherited {
		k, _, ok := strings.Cut(s, "=")
		if ok && !strings.EqualFold(k, "DARKVAULT_TOKEN") && !strings.EqualFold(k, "DARKVAULT_TOKEN_FILE") {
			env[normalize(k)] = s
		}
	}
	names := map[string]bool{}
	valid := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	for k, v := range values {
		if aspnet {
			k = strings.ReplaceAll(k, ":", "__")
		}
		if !valid.MatchString(k) || strings.ContainsRune(v, 0) {
			return nil, errors.New("invalid environment entry")
		}
		name := normalize(k)
		if names[name] {
			return nil, errors.New("environment name collision")
		}
		names[name] = true
		if _, exists := env[name]; exists && !overwrite {
			return nil, errors.New("environment override requires --overwrite-env")
		}
		env[name] = k + "=" + v
	}
	result := make([]string, 0, len(env))
	for _, v := range env {
		result = append(result, v)
	}
	return result, nil
}
