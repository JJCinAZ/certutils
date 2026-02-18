package certutils

import (
	"crypto"
	"crypto/x509"
	"encoding/json"

	"github.com/go-acme/lego/v4/registration"
)

type LegoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string                        { return u.Email }
func (u *LegoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *LegoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *LegoUser) GetUserURI() string                      { return u.Registration.URI }

// GetUserID returns the Let's Encrypt user ID, which is the final part of the user URI:
// e.g. if the URI is "https://acme-v02.api.letsencrypt.org/acme/acct/12345678",
// the user ID is "12345678".
func (u *LegoUser) GetUserID() string {
	userID := u.Registration.URI
	for i := len(userID) - 1; i >= 0; i-- {
		if userID[i] == '/' {
			return userID[i+1:]
		}
	}
	return userID
}

func (u *LegoUser) Marshal() ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(u.key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		Email        string
		Registration *registration.Resource
		Key          []byte
	}{
		Email:        u.Email,
		Registration: u.Registration,
		Key:          keyBytes,
	})
}

func (u *LegoUser) Unmarshal(data []byte) error {
	var aux struct {
		Email        string
		Registration *registration.Resource
		Key          []byte
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	key, err := x509.ParsePKCS8PrivateKey(aux.Key)
	if err != nil {
		return err
	}
	u.Email = aux.Email
	u.Registration = aux.Registration
	u.key = key
	return nil
}

func (c *AcmeClient) SetCacheUser(user *LegoUser) error {
	if c.cacher == nil {
		return nil
	}
	if c.cacheKey == "" {
		c.cacheKey = c.calcCacheKey()
	}
	data, err := user.Marshal()
	if err != nil {
		return err
	}
	return c.cacher.SetUserJSON(c.cacheKey, data)
}

func (c *AcmeClient) GetCachedUser() (*LegoUser, error) {
	if c.cacher == nil {
		return nil, nil
	}
	if c.cacheKey == "" {
		c.cacheKey = c.calcCacheKey()
	}
	data, err := c.cacher.GetUserJSON(c.cacheKey)
	if err != nil || data == nil {
		return nil, err
	}
	user := new(LegoUser)
	if err = user.Unmarshal(data); err != nil {
		return nil, err
	}
	return user, nil
}
