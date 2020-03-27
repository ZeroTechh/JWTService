package jwt

import (
	"time"

	"github.com/ZeroTechh/hades"
	goJwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// Loading the configs
var (
	config      = hades.GetConfig("main.yaml", []string{"../config", "../../config", "config"})
	expirations = config.Map("token").Map("expirationMinutes")
	secret      = []byte(config.Map("JWT").Str("secret"))
	messages    = config.Map("messages")
)

// JWT is a low level JSON web token manager
type JWT struct{}

// isExpired is used to check if expirationTime has already occurred
func (jwt JWT) isExpired(expirationTime time.Time) bool {
	return time.Now().After(expirationTime)
}

// FreshToken is used to generate a fresh access token
func (jwt JWT) FreshToken(userIdentity string) string {
	freshTokenClaims := freshTokenClaims(userIdentity)
	freshToken := goJwt.NewWithClaims(goJwt.SigningMethodHS256, freshTokenClaims)
	freshTokenString, _ := freshToken.SignedString(secret)
	return freshTokenString
}

// AccessAndRefreshTokens is used to generate access and refresh token
func (jwt JWT) AccessAndRefreshTokens(
	userIdentity string, scopesRequested []string) (string, string) {
	accessClaims := accessTokenClaims(userIdentity, scopesRequested)
	refreshClaims := refreshTokenClaims(userIdentity, scopesRequested)

	accessToken := goJwt.NewWithClaims(goJwt.SigningMethodHS256, accessClaims)
	refreshToken := goJwt.NewWithClaims(goJwt.SigningMethodHS256, refreshClaims)

	accessTokenString, _ := accessToken.SignedString(secret)
	refreshTokenString, _ := refreshToken.SignedString(secret)

	return accessTokenString, refreshTokenString
}

// RefreshTokens is used to generate new access and refresh token based on previous refresh token
func (jwt JWT) RefreshTokens(refreshTokenString string) (string, string, string, error) {
	// Validating the refresh token
	valid, claims, msg, err := jwt.ValidateToken(refreshTokenString)
	if err != nil {
		err = errors.Wrap(err, "Error While Validating Refresh Token")
		return "", "", "", err
	} else if !valid || claims.TokenType != typeRefresh {
		return "", "", messages.Str("invalidToken"), nil
	}

	// Decoding the user identity and scopes and adding it to new access and refresh tokens
	userIdentity := claims.UserIdentity
	scopes := claims.Scopes
	accessToken, refreshToken := jwt.AccessAndRefreshTokens(userIdentity, scopes)

	return accessToken, refreshToken, msg, nil
}

// ValidateToken is used to validate any type of token
func (jwt JWT) ValidateToken(tokenString string) (bool, Claims, string, error) {
	// Parsing the token and decoding its claims
	var claims Claims
	token, err := goJwt.ParseWithClaims(tokenString, &claims, jwtKeyFunc)
	if err != nil {
		err = errors.Wrap(err, "Error While Parsing Token")
		return false, Claims{}, "", err
	}

	// Checking if token has expired
	expirationTime := time.Unix(claims.ExpirationUTC, 0)
	if jwt.isExpired(expirationTime) {
		return false, Claims{}, messages.Str("expiredToken"), nil
	}

	return token.Valid, claims, "", nil
}
