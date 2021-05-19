package cidaasutils

import "strings"

type UserAccount struct {
}

type UserIdentity struct {
	Sub          string `json:"sub"`
	Email        string `json:"email"`
	FamilyName   string `json:"family_name"`
	GivenName    string `json:"given_name"`
	MobileNumber string `json:"mobile_number"`
	Locale       string `json:"locale"`
	Provider     string `json:"provider"`
}

type CustomField struct {
	Value interface{} `json:"value"`
}

type UserInfo struct {
	Identity     UserIdentity           `json:"identity"`
	UserAccount  UserAccount            `json:"userAccount"`
	Roles        []string               `json:"roles"`
	CustomFields map[string]CustomField `json:"customFields"`
}

type UserInfoResponse struct {
	Data UserInfo `json:"data"`
}

type UserUpdateRequest struct {
	Email        *string                 `json:"email"`
	FamilyName   *string                 `json:"family_name"`
	GivenName    *string                 `json:"given_name"`
	MobileNumber *string                 `json:"mobile_number"`
	Provider     *string                 `json:"provider"`
	Locale       *string                 `json:"locale"`
	CustomFields *map[string]CustomField `json:"customFields"`
}

type SimpleStatusResponse struct {
	Success bool        `json:"success"`
	Status  int         `json:"status"`
	Data    interface{} `json:"data"`
}

// GetUserProfileInternally returns the internal user profile for the given sub id.
func (u *CidaasUtils) GetUserProfileInternally(sub string) (*UserInfo, error) {
	token, err := u.GetMyAccessToken()
	if err != nil {
		return nil, err
	}

	path := strings.Replace(userinfoInternalEndpoint, "{sub}", sub, 1)

	var result UserInfoResponse
	err = u.doRequest(&RequestInit{Path: path, Token: token.Raw}, &result)
	if err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// UpdateUserProfileInternally updates the user's profile.
func (u *CidaasUtils) UpdateUserProfileInternally(sub string, info *UserUpdateRequest) error {
	token, err := u.GetMyAccessToken()
	if err != nil {
		return err
	}

	path := strings.Replace(userUpdateEndpoint, "{sub}", sub, 1)

	var result SimpleStatusResponse
	err = u.doRequest(&RequestInit{Path: path, Token: token.Raw, Method: "PUT", BodyJSON: *info}, &result)
	if err != nil {
		return err
	}

	return nil
}
