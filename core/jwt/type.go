package jwt

import "github.com/dgrijalva/jwt-go"

// Claims is used to store jwt claims
type Claims struct {
	UserIdentity  string   `json:"UserIdentity"`
	IsFresh       bool     `json:"IsFresh"`
	IsRefresh     bool     `json:"IsRefresh"`
	Scopes        []string `json:"Scopes"`
	CreationUTC   int64    `json:"CreationUTC"`
	ExpirationUTC int64    `json:"ExpirationUTC"`
	jwt.StandardClaims
}
