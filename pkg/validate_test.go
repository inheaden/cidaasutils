package cidaasutils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/apex/log"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

func initTests() *CidaasUtils {
	if err := godotenv.Load("../.env"); err != nil {
		log.Warnf("Error when reading .env file: %s", err.Error())
	}
	utils := New(&Options{
		BaseURL:       os.Getenv("BASE_URL"),
		ClientID:      os.Getenv("CLIENT_ID"),
		ClientSecret:  os.Getenv("CLIENT_SECRET"),
		AdminUsername: os.Getenv("ADMIN_USERNAME"),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
	})
	utils.Init()
	return utils
}

// Payload:
// {
//  "sub": "test",
//  "scopes": ["scope1", "scope2"],
//  "roles": ["role1", "role2"]
// }
var testToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImU0ODFkM2M2LWM0ZDYtNGIwMS1hMDI1LTYzNmU2YzU3MDcwZCJ9.eyJzdWIiOiJ0ZXN0Iiwic2NvcGVzIjpbInNjb3BlMSIsInNjb3BlMiJdLCJyb2xlcyI6WyJyb2xlMSIsInJvbGUyIl19.h-TW3vHo-ocEPiKTtCYyeswUZAL1bhDxrTrDtIBVS2ymD1RTie5ePwVXauUzLBHrnRB67iWE-XRkSdLKLR7pPTXaFu31KSr-aQ5ztNyU3xc2T3pwFde4l3KUtlc4uYxHp-5s1X5gdumAJvamY6qD2_r7C5tVaZ4-Aoc1XMpmUDY`
var expiredTestToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImU0ODFkM2M2LWM0ZDYtNGIwMS1hMDI1LTYzNmU2YzU3MDcwZCJ9.eyJzdWIiOiJ0ZXN0Iiwic2NvcGVzIjpbInNjb3BlMSIsInNjb3BlMiJdLCJyb2xlcyI6WyJyb2xlMSIsInJvbGUyIl0sImV4cCI6MTAwMH0.z1UL27FYTNVOGvBy8JXxap9Pzi8hjufhFhFrH8tLTNk4lozlT2wk4eqL2OVBzg0z5-zl6rnSOQ-V_39FogUO7hVrVb7Gl8iQ5aHEWRFrF7VFACKB7sQd8Vm6Ye64tPATRliqwYbnRG7bqOtbNx_8iGOjOh7rB4WpJB0rNfXYi9w`
var testJwks = json.RawMessage(`{"keys":[{"p":"8V3sZIP64CuoCPOFm45vldsliPkQ2y5FwSFctNftrUAGrLDLEx4-rfCVNFcgX4qVhnz0GbeCQSTM2lNsqzTRJQ","kty":"RSA","q":"7SE4A3628qiySzCOkqekVuuRVfLlGxQ0FTYuNuKsA2iYeFKL0YBskcCzdVGMV2wyMbqaW5cEplBrJYaLv62F0w","d":"sdTSiX8RwDiCzkh9BnmUqrywWcUop8KZAlb5S6raB-uO3r8g2UKnixOtATAfz3q_JJWVuLnCcDaakd6oRj85eopWuVxQDBEOwbLJt7JTKSO3s1cNhvzmtnWb-C_rXrYgl4RZYPdyDTXaKKZXljCAj12xLz1WrF54B1sVBd8WDQE","e":"AQAB","kid":"e481d3c6-c4d6-4b01-a025-636e6c57070d","qi":"W3m2Vil8hYPdpui6cf8eb0aI2kbE-cw_0t7KxkSXcB-3YxLOvV0kL_ht592kucAEFeY6thSpqvEndN1KjKTYbw","dp":"fDHyAz6OBm8wRXrY0tQVwqxCwho2fDFxHxFFnKBG4hDB3nYR6EJ1yhazD32NYNv0WIFPMTRlx5Nh_S1UCzxgKQ","dq":"x4DlQXuArFPl_YCS0ywcBc0Xb7p1qvyqfRYid6bplcyQStsYK2Di9xWrZo7_hiXPbStT5q7-CHcsTlwOg2uYZQ","n":"35NFxF5svtUcysfz0M7x4KeoGvqC-IMRd9P54lGW9S8ZqpQI65Zl5tUPCChkkzluoadWqSvSUV7QvS1jWAqvW58XmPL6kFsN9mNIlulGZjpBkCB1TTt5QoB4dIGrRXbSzig9MoQ424h9apwlHykq9C9XNRw7FnzGBfY_Vn4xmn8"}]}`)

/*
For reference:
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDfk0XEXmy+1RzKx/PQzvHgp6ga+oL4gxF30/niUZb1LxmqlAjr
lmXm1Q8IKGSTOW6hp1apK9JRXtC9LWNYCq9bnxeY8vqQWw32Y0iW6UZmOkGQIHVN
O3lCgHh0gatFdtLOKD0yhDjbiH1qnCUfKSr0L1c1HDsWfMYF9j9WfjGafwIDAQAB
AoGBALHU0ol/EcA4gs5IfQZ5lKq8sFnFKKfCmQJW+Uuq2gfrjt6/INlCp4sTrQEw
H896vySVlbi5wnA2mpHeqEY/OXqKVrlcUAwRDsGyybeyUykjt7NXDYb85rZ1m/gv
6162IJeEWWD3cg012iimV5YwgI9dsS89VqxeeAdbFQXfFg0BAkEA8V3sZIP64Cuo
CPOFm45vldsliPkQ2y5FwSFctNftrUAGrLDLEx4+rfCVNFcgX4qVhnz0GbeCQSTM
2lNsqzTRJQJBAO0hOAN+tvKoskswjpKnpFbrkVXy5RsUNBU2LjbirANomHhSi9GA
bJHAs3VRjFdsMjG6mluXBKZQayWGi7+thdMCQHwx8gM+jgZvMEV62NLUFcKsQsIa
NnwxcR8RRZygRuIQwd52EehCdcoWsw99jWDb9FiBTzE0ZceTYf0tVAs8YCkCQQDH
gOVBe4CsU+X9gJLTLBwFzRdvunWq/Kp9FiJ3pumVzJBK2xgrYOL3Fatmjv+GJc9t
K1Pmrv4IdyxOXA6Da5hlAkBbebZWKXyFg92m6Lpx/x5vRojaRsT5zD/S3srGRJdw
H7djEs69XSQv+G3n3aS5wAQV5jq2FKmq8Sd03UqMpNhv
-----END RSA PRIVATE KEY-----
*/

func TestCidaasUtils_ValidateJWT(t *testing.T) {
	utils := mockUtils()

	token, err := utils.ValidateJWT(testToken)
	assert.Nil(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "RS256", token.Header["alg"])
}

func TestCidaasUtils_ExpiredJWT(t *testing.T) {
	utils := mockUtils()

	token, err := utils.ValidateJWT(expiredTestToken)
	assert.NotNil(t, err)
	assert.Nil(t, token)
	assert.Equal(t, TokenInvalidError, err)
}

func mockUtils() *CidaasUtils {
	utils := New(&Options{BaseURL: "https://example.com"})
	jwks, err := keyfunc.New(testJwks)
	if err != nil {
		panic(err)
	}
	utils.InitWithJWKs(jwks)
	return utils
}

func TestCidaasUtils_JWTInterceptor_NoAuth(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	})).ServeHTTP(w, req)

	assert.Equal(t, 200, w.Result().StatusCode)
}

func TestCidaasUtils_JWTInterceptor_RejectNoAuth(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}), WithAuthorized()).ServeHTTP(w, req)

	assert.Equal(t, 401, w.Result().StatusCode)
}

func TestCidaasUtils_JWTInterceptor_SimpleAuth(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testToken))

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}), WithAuthorized()).ServeHTTP(w, req)

	assert.Equal(t, 200, w.Result().StatusCode)
}

func TestCidaasUtils_JWTInterceptor_RequiredScopes(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testToken))

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}), WithScopes([]string{"scope1"})).ServeHTTP(w, req)

	assert.Equal(t, 200, w.Result().StatusCode)
}

func TestCidaasUtils_JWTInterceptor_MissingScopes(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testToken))

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}), WithScopes([]string{"new-scope"})).ServeHTTP(w, req)

	assert.Equal(t, 403, w.Result().StatusCode)
}

func TestCidaasUtils_JWTInterceptor_RequiredRoles(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testToken))

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}), WithRoles([]string{"role1", "role2"})).ServeHTTP(w, req)

	assert.Equal(t, 200, w.Result().StatusCode)
}

func TestCidaasUtils_JWTInterceptor_MissingRoles(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testToken))

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
	}), WithRoles([]string{"role1", "new-role"})).ServeHTTP(w, req)

	assert.Equal(t, 403, w.Result().StatusCode)
}

func TestCidaasUtils_JWTInterceptor_ContextClaims(t *testing.T) {
	utils := mockUtils()

	// Create a response recorder
	w := httptest.NewRecorder()

	req, _ := http.NewRequest("GET", "", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", testToken))

	// Create the service and process the above request.
	utils.JWTInterceptor(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)
		claims := GetAuthContext(request.Context())
		assert.NotNil(t, claims)
		assert.Equal(t, "test", claims.Sub)
	}), WithRoles([]string{"role1"})).ServeHTTP(w, req)

	assert.Equal(t, 200, w.Result().StatusCode)
}
