# Cidaas Utils

This library contains a few (unofficial) utility functions for working with the [Cidaas](https://cidaas.com) API.

## Features

- Validate a JWT using the provided public JWKs from Cidaas.
- Intercept http requests, validate token and attach to request context.
- Use authentication_code and refresh_token flows.
- Get and update user information.

## Dependencies

The library depends on these libraries

- github.com/MicahParks/keyfunc
- github.com/dgrijalva/jwt-go

## Usage

```go
import (
  "log"
  "http"

  "github.com/inheaden/cidaasutils"
)

func main() {
  utils := cidaasutils.New(&cidaasutils.Options{BaseURL: "https://example.cidaas.com"})
  utils.Init()

  //...

  token, err := utils.ValidateJWT(jwtToken)
  if err != nil {
    log.Fatal(err)
  }
  log.Print(token)

  mux := http.NewServeMux()
  mux.Handle("/", utils.JWTInterceptor(yourHandler, WithRoles([]string{"ADMIN"})))
  http.ListenAndServe(":8000", mux)
}
```
