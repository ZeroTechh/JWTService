package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	typeAccess  = "access"
	typeFresh   = "fresh"
	typeRefresh = "refresh"
)

// claims generates claims for a token.
func claims(id string, scopes []string, tokenType string) Claims {
	expiration := time.Duration(expirations.Int(tokenType)) * time.Minute
	return Claims{
		UserIdentity:  id,
		TokenType:     tokenType,
		Scopes:        scopes,
		CreationUTC:   time.Now().Unix(),
		ExpirationUTC: time.Now().Add(expiration).Unix(),
	}
}

// jwtKeyFunc is used to sign a token.
func jwtKeyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	return secret, nil
}
