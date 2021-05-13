package cidaasutils

import (
	"encoding/json"
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/stretchr/testify/assert"
)

var testToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImJmYjliY2ZiLTEyYjUtNGFhZS1hNzVmLWQzMTVlMjFmZWQ4OCJ9.e30.aFknOm7fWy3JWhZAPPfjwhodbVi02RuFgaygF2Gt6X3rDXb5Z3ZILuwEfJoopfIAeCLRv9lxNGJAc4cBz3JFuTfWqscJaBEEcwFq5W6OEbCAqIBRxGWhwx1-Bq4XKebrKDA_MtJsoOFPlGs9XjuIZl6waZqxQjeB7AzJWiYDYFQ`
var testJwks = json.RawMessage(`{"keys":[{"p":"4MdTIVqq-xNvySUqfG8_1-D7IeDb-mNE1y4wh_D8ji8dEYJIm32aeU2D0wpkX2tzmPd9_sKzTsPPs1vzTIkaQQ","kty":"RSA","q":"nv2KFC5FsYz9VpEnRyiU0AfW2BoxhCOdjljoS1KEudy6sIy0XaAH4alrfM7VOmS8tOSc-dBzt0pFjQqkbsKJhQ","d":"EUVUwh9vZbAQqqKqk_HgrOpysnQ_O5t5vYFrc-qJlLVyh38CiKjeoceUAK49JoxuWM5LrPEgZ62VlRmKu44iQkb3YrUUtWleC9k8Qa_ELmzYBCsFFxjv15VdRkooG31c5c41SHl01QDP8xio2cED2ZcP-2E5Suqr5PB5I5DZDAE","e":"AQAB","kid":"bfb9bcfb-12b5-4aae-a75f-d315e21fed88","qi":"geDP5WL-3m-xtr4b1vHRqus9ahHUUss9NHxewayFtoTnk2d3Imik80hHa7S-mtd-rSGxKmCB26lQi-fZQVpOiA","dp":"pPE_TDt3OjTCE80lBxivtZ9PSUXyxiLwEiK_1BF_kmp6Hy4GT6t0nkzGTifTDb4QnpAGMdr3rvW7RPdVarU0wQ","dq":"c_66bLrNshoRAsVoCKx81cHCZ2vE0IlDfAU1hS6xEwENW51sQhptZaA7gZVNUAsK-lcIh-IjaohPcfVfvkdEGQ","n":"i5mjiOjvnfpkHGUzW7RebjpWCQ9Vv-16KIOhMdK1FVAsW_3KcMM6z5KO-WCMFgZ4JUb-NTIOK6J0h1xQ_WAKoKtkrh2lj77LyKpC2gl-QxHytAOea0TnIzlZ_6yxbwPb82NvT0cUvrKEYeF3Cy7kWhLNqJX1qr-Le08-LfWJbMU"}]}`)

func TestValidateKey(t *testing.T) {
	utils := NewCidaasUtils(&Options{BaseURL: "https://example.com"})
	jwks, err := keyfunc.New(testJwks)
	if err != nil {
		panic(err)
	}
	utils.InitWithJWKs(jwks)

	token, result := utils.ValidateJWT(testToken)
	assert.Nil(t, result)
	assert.NotNil(t, token)
	assert.Equal(t, "RS256", token.Header["alg"])
}
