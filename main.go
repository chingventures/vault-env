package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

type LoginRequest struct {
	Role  string `json:"role"`
	Nonce string `json:"nonce"`
	PKCS7 string `json:"pkcs7"`
}

func login(c *api.Client, role string, pkcs7 string, nonce string) (string, error) {
	request := LoginRequest{Role: role, PKCS7: pkcs7, Nonce: nonce}

	r := c.NewRequest("POST", "/v1/auth/aws-ec2/login")

	if err := r.SetJSONBody(request); err != nil {
		return "", err
	}

	resp, err := c.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}

	if resp != nil && resp.StatusCode == 404 {
		fmt.Println("404")
		return "", nil
	}

	if err != nil {
		return "", err
	}

	res, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", err
	}

	return res.Auth.ClientToken, nil
}

func ReadNonce(path string) (string, error) {
	res, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(res)), nil
}

func ReadPKCS7() (string, error) {
	metadataUrl := "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7"
	res, err := http.Get(metadataUrl)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	bts, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(bts), err
}

func NewClient(nonceFilename string) *api.Client {
	nonce, err := ReadNonce(nonceFilename)
	if err != nil {
		fmt.Println("Can't read nonce")
		fmt.Println(err)
		os.Exit(1)
	}

	pkcs7, err := ReadPKCS7()
	if err != nil {
		fmt.Println("Couldn't read PKCS7")
		fmt.Println(err)
		os.Exit(1)
	}

	config := api.DefaultConfig()

	client, err := api.NewClient(config)

	if err != nil {
		fmt.Println("Failed to initialise client")
		os.Exit(1)
	}

	clientToken, err := login(client, "apps-role", pkcs7, nonce)
	if err != nil {
		fmt.Println("Login failed")
		fmt.Println(err)
		os.Exit(2)
	}
	client.SetToken(clientToken)

	return client
}

type Data map[string]interface{}

func ProcessSecret(client *api.Client, path string) Data {
	secret, err := client.Logical().Read(path)
	if err != nil {
		fmt.Println("Failed to read secret")
		fmt.Println(err)
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
	path := exportParts[1]

	parts := strings.Split(path, ".")
	m := data[parts[0]]
	res := m[parts[1]]
	fmt.Println(fmt.Sprintf("export %s=%s", exportKey, res))
}

func main() {
	secrets := flag.String("secrets", "", "Comma separated list of secrets to fetch")
	exports := flag.String("exports", "", "Comma separated list of export output")
	nonceFilename := flag.String("nonce-filename", "", "Path to the file containing the vault nonce")
	flag.Parse()
	if len(*secrets) < 1 {
		fmt.Println("No secrets specified")
		os.Exit(2)
	}

	client := NewClient(*nonceFilename)

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
