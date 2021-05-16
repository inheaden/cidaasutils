package cidaasutils

import (
	"net/url"

	"github.com/dgrijalva/jwt-go"
)

type AccessTokenResult struct {
	Sub          string `json:"sub"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// GetMyAccessToken returns the access token for the configured user.
// It will use the Admin credentials.
func (u *CidaasUtils) GetMyAccessToken() (*jwt.Token, error) {
	accessToken := u.myAccessToken
	if accessToken != nil && !IsTokenExpired(accessToken) {
		return accessToken, nil
	}

	data := url.Values{}
	data.Add("grant_type", "password")
	data.Add("client_id", u.options.ClientID)
	data.Add("client_secret", u.options.ClientSecret)
	data.Add("username", u.options.AdminUsername)
	data.Add("password", u.options.AdminPassword)

	var result AccessTokenResult
	err := u.doRequest(&RequestInit{Path: tokenEndpoint, BodyForm: &data, Method: "POST"}, &result)
	if err != nil {
		return nil, err
	}

	token, err := u.ValidateJWT(result.AccessToken)
	if err != nil {
		return nil, err
	}
	accessToken = token
	return token, err
}

func IsTokenExpired(token *jwt.Token) bool {
	return false
}

// AuthorizationCodeFlow completes the authorization flow using a code and a redirect URL.
// The redirect URL has to match the one used to create the authorization code.
func (u *CidaasUtils) AuthorizationCodeFlow(code string, redirectURL string) (*AccessTokenResult, error) {
	data := url.Values{}
	data.Add("grant_type", "authorization_code")
	data.Add("client_id", u.options.ClientID)
	data.Add("client_secret", u.options.ClientSecret)
	data.Add("code", code)
	data.Add("redirect_uri", redirectURL)

	var result AccessTokenResult
	err := u.doRequest(&RequestInit{Path: tokenEndpoint, BodyForm: &data, Method: "POST"}, &result)
	if err != nil {
		return nil, err
	}

	_, err = u.ValidateJWT(result.AccessToken)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// RefreshTokenFlow retrieves a new access token and refresh token.
func (u *CidaasUtils) RefreshTokenFlow(refreshToken string) (*AccessTokenResult, error) {
	data := url.Values{}
	data.Add("grant_type", "refresh_token")
	data.Add("client_id", u.options.ClientID)
	data.Add("client_secret", u.options.ClientSecret)
	data.Add("refresh_token", refreshToken)

	var result AccessTokenResult
	err := u.doRequest(&RequestInit{Path: tokenEndpoint, BodyForm: &data, Method: "POST"}, &result)
	if err != nil {
		return nil, err
	}

	_, err = u.ValidateJWT(result.AccessToken)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
