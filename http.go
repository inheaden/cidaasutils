package cidaasutils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Default endpoints
var jwkEndpoint = ".well-known/jwks.json"
var userinfoInternalEndpoint = "users-srv/internal/userinfo/profile/{sub}"
var userUpdateEndpoint = "users-srv/user/{sub}"
var tokenEndpoint = "token-srv/token"

var NoResultError = errors.New("no results")

type RequestInit struct {
	Path     string
	Token    string
	Method   string
	BodyForm *url.Values
	BodyJSON interface{}
	Context  context.Context
}

// buildURL builds a url to talk with cidaas
func (u *CidaasUtils) buildUrl(path string) string {
	return fmt.Sprintf("%s/%s", u.options.BaseURL, path)
}

func (u *CidaasUtils) buildRequest(init *RequestInit) (*http.Request, error) {
	var ctx context.Context
	if init.Context != nil {
		ctx, _ = context.WithTimeout(init.Context, time.Second*30)
	} else {
		ctx, _ = context.WithTimeout(context.Background(), time.Second*30)
	}

	var body io.Reader
	if init.BodyForm != nil {
		body = strings.NewReader(init.BodyForm.Encode())
	} else if init.BodyJSON != nil {
		requestBody, err := json.Marshal(init.BodyJSON)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(requestBody)
	}

	res, err := http.NewRequestWithContext(ctx, init.Method, u.buildUrl(init.Path), body)
	if err != nil {
		return nil, err
	}

	if init.BodyForm != nil {
		res.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res.Header.Add("Content-Length", strconv.Itoa(len(init.BodyForm.Encode())))
	} else if init.BodyJSON != nil {
		res.Header.Add("Content-Type", "application/json")
	}

	if init.Token != "" {
		res.Header.Add("Authorization", fmt.Sprintf("Bearer %s", init.Token))
	}

	return res, err
}

func (u *CidaasUtils) doRequest(init *RequestInit, result interface{}) error {
	res, err := u.buildRequest(init)
	resp, err := doRequest(res)
	if err != nil {
		return err
	}

	if resp.StatusCode == 204 {
		return NoResultError
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, result)
	return err
}

func doRequest(request *http.Request) (*http.Response, error) {
	log.Print(request.URL)
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Cidaas Error: error body: %s", string(b))
		return nil, errors.New(fmt.Sprintf("Cidaas Error: request to %s was not successful, status code was %d", request.URL, resp.StatusCode))
	}

	return resp, err
}
