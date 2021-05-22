package cidaasutils

import (
	"log"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/dgrijalva/jwt-go"
)

type Options struct {
	// This is the base url for communicating with Cidaas.
	// Usually something like https://your-company.cidaas.com
	BaseURL string

	// App credentials
	ClientID     string
	ClientSecret string

	// Credentials for an admin user (used to retrieve an access_token)
	AdminUsername string
	AdminPassword string

	// Interval how often the JWKs will be refreshed from Cidaas.
	// Default is one hour.
	RefreshInterval time.Duration
}

type ICidaasUtils interface {
	Init() error
	ValidateJWT(token string) (*jwt.Token, error)
	GetUserProfileInternally(sub string) (*UserInfo, error)
	UpdateUserProfileInternally(sub string, info *UserUpdateRequest) error
	JWTInterceptor(next http.Handler, options ...JWTInterceptorOption) http.Handler
	GetMyAccessToken() (*jwt.Token, error)
	AuthorizationCodeFlow(code string, redirectURL string) (*AccessTokenResult, error)
	RefreshTokenFlow(refreshToken string) (*AccessTokenResult, error)
}

// CidaasUtils is the main struct for all utils functions.
type CidaasUtils struct {
	options       *Options
	jwks          *keyfunc.JWKS
	myAccessToken *jwt.Token
}

// making sure that the interface is implemented
var _ ICidaasUtils = &CidaasUtils{}

// New creates a new instance of the utils.
func New(options *Options) *CidaasUtils {
	return &CidaasUtils{options: options}
}

// Init initializes the JWKs and sets up a refresh interval.
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

	jwks, err := keyfunc.Get(u.buildUrl(jwkEndpoint), options)
	if err != nil {
		return err
	}
	u.jwks = jwks

	return nil
}

// InitWithJWKs initializes the JWKs without needing to talk to a server.
func (u *CidaasUtils) InitWithJWKs(jwks *keyfunc.JWKS) {
	u.jwks = jwks
}
