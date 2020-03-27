package jwt

import "github.com/dgrijalva/jwt-go"

// Claims is used to store jwt claims
type Claims struct {
	UserIdentity  string   `json:"UserIdentity"`
	TokenType     string   `json:"TokenType"`
	Scopes        []string `json:"Scopes"`
	CreationUTC   int64    `json:"CreationUTC"`
	ExpirationUTC int64    `json:"ExpirationUTC"`
	jwt.StandardClaims
}
