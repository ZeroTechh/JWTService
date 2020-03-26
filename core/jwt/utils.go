package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// makeClaims is used to generate claims for a token
func makeClaims(
	userIdentity string,
	scopes []string,
	isFresh bool,
	isRefresh bool) Claims {
	typeName := "access"
	if isFresh {
		typeName = "fresh"
	} else if isRefresh {
		typeName = "refresh"
	}

	expiration := time.Duration(expirations.Int(typeName)) * time.Minute
	currentTime := time.Now()
	expirationTime := currentTime.Add(expiration)

	return Claims{
		UserIdentity:  userIdentity,
		IsFresh:       isFresh,
		IsRefresh:     isRefresh,
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
		true,
		false,
	)
}

// accessTokenClaims is used to make claims for access token
func accessTokenClaims(userIdentity string, scopes []string) Claims {
	return makeClaims(
		userIdentity,
		scopes,
		false,
		false,
	)
}

// refreshTokenClaims is used to make claims for refresh token
func refreshTokenClaims(userIdentity string, scopes []string) Claims {
	return makeClaims(
		userIdentity,
		scopes,
		false,
		true,
	)
}

// jwtKeyFunc is used to sign a token
func jwtKeyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	return secret, nil
}
