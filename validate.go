package cidaasutils

import (
	"context"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// TokenInvalidError is returned if the given token is invalid
var TokenInvalidError = errors.New("token is invalid")

// CidaasClaimKey Key used for storing the claims on the context
var CidaasClaimKey = "CIDAAS_CLAIMS"

// ValidateJWT validates the given jwt and returns the parsed token.
func (u *CidaasUtils) ValidateJWT(jwtToken string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &jwt.MapClaims{}, u.jwks.KeyFunc)
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); ok {
			return nil, TokenInvalidError
		}
		return nil, err
	}

	// Check if issuer is valid
	if !token.Claims.(*jwt.MapClaims).VerifyIssuer(u.options.BaseURL, true) {
		return nil, TokenInvalidError
	}
	return token, nil
}

// ToCidaasClaims returns claims of the given token
func (u *CidaasUtils) ToCidaasTokenClaims(jwtToken *jwt.Token) (*CidaasTokenClaims, error) {
	return toCidaasTokenClaims(jwtToken.Claims)
}

// CidaasTokenClaims describe the claims on a given token
type CidaasTokenClaims struct {
	Sub       string   `json:"sub,omitempty"`
	Email     string   `json:"email,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	// Other contains all non-standard claims of the token
	Other jwt.MapClaims
}

func (c *CidaasTokenClaims) Valid() error {
	now := jwt.TimeFunc().Unix()
	if now >= c.ExpiresAt {
		return TokenInvalidError
	}
	return nil
}

// JWTInterceptorOption can be used to customize the Interceptor
type JWTInterceptorOption func(option *jwtInterceptorOptions)

type jwtInterceptorOptions struct {
	RejectUnauthorized bool
	Scopes             []string
	Roles              []string
}

// WithAuthorized allows only requests which contain a valid token
func WithAuthorized() JWTInterceptorOption {
	return func(option *jwtInterceptorOptions) {
		option.RejectUnauthorized = true
	}
}

// WithScopes allows only requests which contain a JWT with all of the provided scopes.
func WithScopes(scopes []string) JWTInterceptorOption {
	return func(option *jwtInterceptorOptions) {
		option.Scopes = scopes
	}
}

// WithRoles allows only requests which contain a JWT with all of the provided roles.
func WithRoles(roles []string) JWTInterceptorOption {
	return func(option *jwtInterceptorOptions) {
		option.Roles = roles
	}
}

// JWTInterceptor parses and validates Bearer token in requests, compares them to the
// given option constraints and attaches the CidaasTokenClaims to the request context.
func (u *CidaasUtils) JWTInterceptor(next http.Handler, options ...JWTInterceptorOption) http.Handler {
	option := &jwtInterceptorOptions{}

	for _, o := range options {
		o(option)
	}

	return u.jwtInterceptor(next, option)
}

func (u *CidaasUtils) jwtInterceptor(next http.Handler, option *jwtInterceptorOptions) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		authorizationHeader := request.Header.Get("Authorization")
		if (authorizationHeader == "" || !strings.HasPrefix(authorizationHeader, "Bearer ")) && option.RejectUnauthorized {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		} else if authorizationHeader == "" {
			// nothing to parse, continue
			next.ServeHTTP(writer, request)
			return
		}

		// parse and validate token
		token := strings.TrimPrefix(authorizationHeader, "Bearer ")
		parsed, err := u.ValidateJWT(token)
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		// create claims
		claims, err := toCidaasTokenClaims(parsed.Claims)
		if err != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		// verify scopes
		if len(option.Scopes) > 0 && !includesStrings(claims.Scopes, option.Scopes) {
			writer.WriteHeader(http.StatusForbidden)
			return
		}

		// verify roles
		if len(option.Roles) > 0 && !includesStrings(claims.Roles, option.Roles) {
			writer.WriteHeader(http.StatusForbidden)
			return
		}

		// attach to context
		request = request.WithContext(
			setAuthContext(
				request.Context(), claims,
			),
		)

		next.ServeHTTP(writer, request)
	}
}

func toCidaasTokenClaims(claims jwt.Claims) (*CidaasTokenClaims, error) {
	mapClaims := claims.(*jwt.MapClaims)
	result := &CidaasTokenClaims{}

	err := mapstructure.Decode(claims, &result)
	if err != nil {
		return nil, err
	}

	result.Other = *mapClaims

	return result, nil
}

func setAuthContext(ctx context.Context, claims *CidaasTokenClaims) context.Context {
	return context.WithValue(ctx, CidaasClaimKey, claims)
}

// GetAuthContext returns the CidaasTokenClaims from the request context if it exists otherwise nil.
func GetAuthContext(ctx context.Context) *CidaasTokenClaims {
	c := ctx.Value(CidaasClaimKey)
	result, ok := c.(*CidaasTokenClaims)
	if !ok {
		return nil
	}
	return result
}
