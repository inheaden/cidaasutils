# Cidaas Utils

This library contains a few (unofficial) utility functions for working with the [Cidaas](https://cidaas.com) API.

## Features

- Validate a JWT using the provided public JWKs from Cidaas.

## Dependencies

The library depends on these libraries

- github.com/MicahParks/keyfunc
- github.com/dgrijalva/jwt-go

## Usage

```go
import (
  "log"

  "github.com/inheaden/cidaasutils"
)

func main() {
  utils := NewCidaasUtils(&Options{BaseURL: "https://example.com"})
  utils.Init()

  //...

  token, err := utils.ValidateJWT(jwtToken)
  if err != nil {
    log.Fatal(err)
  }
  log.Print(token)
}
```
