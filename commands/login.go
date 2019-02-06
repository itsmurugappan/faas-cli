// Copyright (c) OpenFaaS Author(s) 2017. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package commands

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"strconv"
	"encoding/json"
	"github.com/openfaas/faas-cli/proxy"

	"github.com/openfaas/faas-cli/config"
	"github.com/spf13/cobra"
)

var (
	username      string
	password      string
	passwordStdin bool
	authEndPoint  string
	oidcClient        string
)

type accessToken struct {
	Token string `json:"access_token"`
}

func init() {
	loginCmd.Flags().StringVarP(&gateway, "gateway", "g", defaultGateway, "Gateway URL starting with http(s)://")
	loginCmd.Flags().StringVarP(&username, "username", "u", "", "Gateway username")
	loginCmd.Flags().StringVarP(&password, "password", "p", "", "Gateway password")
	loginCmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Reads the gateway password from stdin")
	loginCmd.Flags().BoolVar(&tlsInsecure, "tls-no-verify", false, "Disable TLS validation")
	loginCmd.Flags().StringVarP(&authEndPoint, "auth-url", "a", "", "oidc provider like key cloak")
	loginCmd.Flags().StringVarP(&oidcClient, "client", "c", "", "oidc client")
	faasCmd.AddCommand(loginCmd)
}

var loginCmd = &cobra.Command{
	Use:   `login [--username USERNAME] [--password PASSWORD] [--gateway GATEWAY_URL] [--auth-url AUTH_URL] [--client OIDC_CLIENT][--tls-no-verify]`,
	Short: "Log in to OpenFaaS gateway",
	Long:  "Log in to OpenFaaS gateway.\nIf no gateway is specified, the default local one will be used.",
	Example: `  faas-cli login -u user -p password --gateway http://127.0.0.1:8080 --auth-url=https://oidcprovider/auth/realms/realmname/protocol/openid-connect/token --client=oidcclientname
  faas-cli login -u user -p password --gateway http://127.0.0.1:8080
  cat ~/faas_pass.txt | faas-cli login -u user --password-stdin --gateway https://openfaas.mydomain.com`,
	RunE: runLogin,
}

func runLogin(cmd *cobra.Command, args []string) error {

	if len(username) == 0 {
		return fmt.Errorf("must provide --username or -u")
	}

	if len(password) > 0 {
		fmt.Println("WARNING! Using --password is insecure, consider using: cat ~/faas_pass.txt | faas-cli login -u user --password-stdin")
		if passwordStdin {
			return fmt.Errorf("--password and --password-stdin are mutually exclusive")
		}

		if len(username) == 0 {
			return fmt.Errorf("must provide --username with --password")
		}
	}

	if passwordStdin {
		if len(username) == 0 {
			return fmt.Errorf("must provide --username with --password-stdin")
		}

		passwordStdin, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}

		password = strings.TrimSpace(string(passwordStdin))
	}

	password = strings.TrimSpace(password)
	if len(password) == 0 {
		return fmt.Errorf("must provide a non-empty password via --password or --password-stdin")
	}

	fmt.Println("Calling the OpenFaaS server to validate the credentials...")

	gateway = getGatewayURL(gateway, defaultGateway, "", os.Getenv(openFaaSURLEnvironment))

	if len(authEndPoint) > 0 {
		token,err := getAccessToken(username, password, authEndPoint, oidcClient)

		if err != nil {
			return err
		}

		if err := config.UpdateAuthConfig(gateway, "", "", token); err != nil {
			return err
		}

	} else {
		if err := validateLogin(gateway, username, password); err != nil {
			return err
		}
		if err := config.UpdateAuthConfig(gateway, username, password,""); err != nil {
			return err
		}
	}

	_, _, _, err := config.LookupAuthConfig(gateway)
	if err != nil {
		return err
	}
	fmt.Println("credentials saved for", gateway)

	return nil
}

func validateLogin(gatewayURL string, user string, pass string) error {
	timeout := time.Duration(5 * time.Second)
	client := proxy.MakeHTTPClient(&timeout, tlsInsecure)

	req, err := http.NewRequest("GET", gatewayURL+"/system/functions", nil)
	if err != nil {
		return fmt.Errorf("invalid URL: %s", gatewayURL)
	}

	req.SetBasicAuth(user, pass)
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot connect to OpenFaaS on URL: %s. %v", gatewayURL, err)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	if res.TLS == nil {
		fmt.Println("WARNING! Communication is not secure, please consider using HTTPS. Letsencrypt.org offers free SSL/TLS certificates.")
	}

	switch res.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("unable to login, either username or password is incorrect")
	default:
		bytesOut, err := ioutil.ReadAll(res.Body)
		if err == nil {
			return fmt.Errorf("server returned unexpected status code: %d - %s", res.StatusCode, string(bytesOut))
		}
	}

	return nil
}

func getAccessToken(user string, pass string, authEndPoint string, oidcClient string) (string,error) {
	timeout := time.Duration(5 * time.Second)
	client := proxy.MakeHTTPClient(&timeout, tlsInsecure)

	apiUrl := authEndPoint
	data := url.Values{}
	data.Set("username", user)
	data.Set("password", pass)
	data.Set("grant_type", "password")
	data.Set("client_id", oidcClient)

	u, err := url.ParseRequestURI(apiUrl)
	if err != nil {
		return "", err
	}

	urlStr := u.String()

	r, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	res, _ := client.Do(r)

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)

	if readErr != nil {
		return "", readErr
	}

	token := accessToken{}
	jsonErr := json.Unmarshal(body, &token)
	if jsonErr != nil {
		return "", jsonErr
	}

	if res.TLS == nil {
		fmt.Println("WARNING! Communication is not secure, please consider using HTTPS. Letsencrypt.org offers free SSL/TLS certificates.")
	}

	return token.Token,nil
}
