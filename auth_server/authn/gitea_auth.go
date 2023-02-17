/*
   Copyright 2023 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cesanta/docker_auth/auth_server/api"
)

type GiteaAuthConfig struct {
	ApiUri      string        `yaml:"api_uri,omitempty"`
	HTTPTimeout time.Duration `yaml:"http_timeout,omitempty"`
	TokenDB     string        `yaml:"token_db,omitempty"`
}

type GiteaAuth struct {
	config *GiteaAuthConfig
	client *http.Client
}

type GiteaOrganization struct {
	Id       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	/** @deprecated */
	Username    string `json:"username"`
	AvatarUrl   string `json:"avatar_url"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Website     string `json:"website"`
}

func NewGiteaAuth(c *GiteaAuthConfig) (*GiteaAuth, error) {
	return &GiteaAuth{
		config: c,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (gta *GiteaAuth) getApiUri() string {
	if gta.config.ApiUri != "" {
		return gta.config.ApiUri
	} else {
		return "https://gitea.com/api"
	}
}

func (gta *GiteaAuth) fetchUserOrgs(user string, password string) ([]*GiteaOrganization, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/user/orgs", gta.getApiUri()), nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request to gitea api: %s", err)
	}

	req.SetBasicAuth(user, password)
	resp, err := gta.client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, api.WrongPass
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not get user orgs, statusCode: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("could not read response body: %s", err)
	}

	var orgs []*GiteaOrganization
	err = json.Unmarshal(body, &orgs)
	if err != nil {
		return nil, fmt.Errorf("could not parse gitea response: %s", err)
	}

	return orgs, nil
}

func (gta *GiteaAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	orgs, err := gta.fetchUserOrgs(user, string(password))
	if err != nil {
		return false, nil, err
	}

	if err != nil {
		return false, nil, fmt.Errorf("could not hash password: %s", err)
	}

	var groups []string

	for _, org := range orgs {
		groups = append(groups, org.Name)
	}

	labels := api.Labels{
		"group": groups,
	}

	return true, labels, nil
}

func (gta *GiteaAuth) Stop() {
}

func (gta *GiteaAuth) Name() string {
	return "Gitea"
}
