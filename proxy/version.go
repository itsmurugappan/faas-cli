// Copyright (c) OpenFaaS Author(s) 2018. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package proxy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	"strings"
)

//GetSystemInfo get system information from /system/info endpoint
func GetSystemInfo(gateway string, tlsInsecure bool) (map[string]interface{}, error) {
	infoEndPoint := gateway + "/system/info"
	timeout := 5 * time.Second

	client := MakeHTTPClient(&timeout, tlsInsecure)
	req, err := http.NewRequest(http.MethodGet, infoEndPoint, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP method or invalid URL")
	}

	SetAuth(req, gateway)

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to OpenFaaS on URL: %s", gateway)
	}

	if response.Body != nil {
		defer response.Body.Close()
	}
	info := make(map[string]interface{})

	switch response.StatusCode {
	case http.StatusOK:
		bytesOut, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("cannot read result from OpenFaaS on URL: %s", gateway)
		}
		jsonErr := json.Unmarshal(bytesOut, &info)
		if jsonErr != nil {
			if strings.Contains(string(bytesOut),"Log in to openfaas") {
				fmt.Println("unauthorized access, run \"faas-cli login\" to setup authentication for this server")
				return nil, fmt.Errorf("unauthorized access, run \"faas-cli login\" to setup authentication for this server")
			} else {
				return nil, fmt.Errorf("cannot parse result from OpenFaaS on URL: %s\n%s", gateway, jsonErr.Error())
			}
		}

	case http.StatusUnauthorized:
		return nil, fmt.Errorf("unauthorized access, run \"faas-cli login\" to setup authentication for this server")
	default:
		bytesOut, err := ioutil.ReadAll(response.Body)
		if err == nil {
			return nil, fmt.Errorf("server returned unexpected status code: %d - %s", response.StatusCode, string(bytesOut))
		}
	}

	return info, nil
}
