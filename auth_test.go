package cidaasutils

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAccessToken(t *testing.T) {
	utils := initTests()

	token, err := utils.GetMyAccessToken()
	assert.Nil(t, err)
	assert.NotNil(t, token)
	log.Print(token)
}

func DisabledTestAuthorizationCodeFlow(t *testing.T) {
	utils := initTests()

	token, err := utils.AuthorizationCodeFlow("27b37529-7c94-4c80-b610-b55fa5761e75", "xxx")
	assert.Nil(t, err)
	assert.NotNil(t, token)
	log.Print(token)
}

func TestRefreshTokenFlow(t *testing.T) {
	utils := initTests()

	token, err := utils.RefreshTokenFlow(os.Getenv("REFRESH_TOKEN"))
	assert.Nil(t, err)
	assert.NotNil(t, token)
	log.Print(token)
}
