package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

type Data map[string]interface{}

func ProcessSecret(client *api.Client, path string) Data {
	secret, err := client.Logical().Read(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read secret")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	result := make(Data)
	for key, value := range secret.Data {
		result[key] = value
	}
	return result
}

func ProcessExport(export string, data map[string]Data) {
	exportParts := strings.SplitN(export, "=", 2)
	exportKey := exportParts[0]
	if len(os.Getenv(exportKey)) != 0 {
		fmt.Println(fmt.Sprintf("# %s is already set, ignoring", exportKey))
		return
	}

	path := exportParts[1]

	parts := strings.Split(path, ".")
	m := data[parts[0]]
	res := m[parts[1]]
	fmt.Println(fmt.Sprintf("export %s=%s", exportKey, res))
}

func main() {
	secrets := flag.String("secrets", "", "Comma separated list of secrets to fetch")
	exports := flag.String("exports", "", "Comma separated list of export output")
	flag.Parse()
	if len(*secrets) < 1 {
		fmt.Fprintln(os.Stderr, "No secrets specified")
		os.Exit(2)
	}

	config := api.DefaultConfig()

	client, err := api.NewClient(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	result := make(map[string]Data)
	secretList := strings.Split(*secrets, ",")
	for _, secret := range secretList {
		result[secret] = ProcessSecret(client, secret)
	}

	if len(*exports) > 0 {
		exportList := strings.Split(*exports, ",")
		for _, export := range exportList {
			ProcessExport(export, result)
		}
	}
}
