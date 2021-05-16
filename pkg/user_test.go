package cidaasutils

import (
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestCidaasUtils_GetUserProfileInternally(t *testing.T) {
	utils := initTests()

	user, err := utils.GetUserProfileInternally("fc7cc753-b137-455a-8b01-96165e05dd01")
	assert.Nil(t, err)
	assert.NotNil(t, user)
	log.Print(user)
}

func TestCidaasUtils_UpdateUserProfileInternally(t *testing.T) {
	utils := initTests()

	err := utils.UpdateUserProfileInternally("fc7cc753-b137-455a-8b01-96165e05dd01",
		&UserUpdateRequest{Provider: "self"})
	assert.Nil(t, err)
}
