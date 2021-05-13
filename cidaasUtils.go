package cidaasutils

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/dgrijalva/jwt-go"
)

// Default endpoint for Cidaas JWKs
var jwkEnpoint = "/.well-known/jwks.json"

// TokenInvalid is returned if the given token is invalid
var TokenInvalid = errors.New("Token is invalid")

type Options struct {
	// This is the base url for communicating with Cidaas.
	// Usually something like https://your-company.cidaas.com
	BaseURL string

	// Interval how often the JWKs will be refreshed from Cidaas.
	// Default is one hour.
	RefreshInterval time.Duration
}

type ICidaasUtils interface {
	Init() error
	ValidateJWT(token string) (*jwt.Token, error)
}

// CidaasUtils is the main struct for all utils functions.
type CidaasUtils struct {
	options *Options
	jwks    *keyfunc.JWKS
}

// making sure that the interface is implemented
var _ ICidaasUtils = &CidaasUtils{}

// NewCidaasUtils creates a new instance of the utils.
func NewCidaasUtils(options *Options) *CidaasUtils {
	return &CidaasUtils{options: options}
}

// Init initilizes the JWKs and sets up a refresh interval.
func (u *CidaasUtils) Init() error {
	refreshInterval := time.Hour
	if u.options.RefreshInterval != 0 {
		refreshInterval = u.options.RefreshInterval
	}

	options := keyfunc.Options{
		RefreshInterval: &refreshInterval,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
	}

	jwks, err := keyfunc.Get(u.buildUrl(jwkEnpoint), options)
	if err != nil {
		return err
	}
	u.jwks = jwks

	return nil
}

// InitWithJWKs initilizes the JWKs without needing to talk to a server.
func (u *CidaasUtils) InitWithJWKs(jwks *keyfunc.JWKS) {
	u.jwks = jwks
}

// ValidateJWT validates the given jwt and returns the parsed token.
func (u *CidaasUtils) ValidateJWT(jwtToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(jwtToken, u.jwks.KeyFunc)
	if err != nil {
		return nil, err
	}

	// Check if the token is valid.
	if !token.Valid {
		return nil, TokenInvalid
	}
	return token, nil
}

// buildURL builds a url to talk with cidaas
func (u *CidaasUtils) buildUrl(path string) string {
	return fmt.Sprintf("%s/%s", u.options.BaseURL, path)
}
