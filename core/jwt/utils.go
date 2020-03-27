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

// makeClaims is used to generate claims for a token
func makeClaims(
	userIdentity string,
	scopes []string,
	tokenType string) Claims {
	expiration := time.Duration(expirations.Int(tokenType)) * time.Minute
	currentTime := time.Now()
	expirationTime := currentTime.Add(expiration)

	return Claims{
		UserIdentity:  userIdentity,
		TokenType:     tokenType,
		Scopes:        scopes,
		CreationUTC:   currentTime.Unix(),
		ExpirationUTC: expirationTime.Unix(),
	}
}

// freshTokenClaims is used to make claims for a fresh access token
func freshTokenClaims(userIdentity string) Claims {
	return makeClaims(
		userIdentity,
		nil,
		typeFresh,
	)
}

// accessTokenClaims is used to make claims for access token
func accessTokenClaims(userIdentity string, scopes []string) Claims {
	return makeClaims(
		userIdentity,
		scopes,
		typeAccess,
	)
}

// refreshTokenClaims is used to make claims for refresh token
func refreshTokenClaims(userIdentity string, scopes []string) Claims {
	return makeClaims(
		userIdentity,
		scopes,
		typeRefresh,
	)
}

// jwtKeyFunc is used to sign a token
func jwtKeyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	return secret, nil
}
