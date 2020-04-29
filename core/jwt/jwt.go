package jwt

import (
	"time"

	"github.com/ZeroTechh/hades"
	goJwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

var (
	config      = hades.GetConfig("main.yaml", []string{"../config", "../../config", "config"})
	expirations = config.Map("token").Map("expirationMinutes")
	secret      = []byte(config.Map("JWT").Str("secret"))
	messages    = config.Map("messages")
	method      = goJwt.SigningMethodHS256
)

func token(c Claims) (string, error) {
	t, err := goJwt.NewWithClaims(method, c).SignedString(secret)
	return t, errors.Wrap(err, "Error while signing")
}

// Fresh generates a fresh access token.
func Fresh(id string) (string, error) {
	t, err := token(claims(id, nil, typeFresh))
	return t, errors.Wrap(err, "Error while creating token")
}

// AccessAndRefresh generates a access and refresh token.
func AccessAndRefresh(id string, scopes []string) (string, string, error) {
	access, err := token(claims(id, scopes, typeAccess))
	if err != nil {
		return "", "", errors.Wrap(err, "Error while creating token")
	}

	refresh, err := token(claims(id, scopes, typeRefresh))
	err = errors.Wrap(err, "Error while creating token")

	return access, refresh, err
}

// Valid validates any type of token.
func Valid(t, tokenType string) (Claims, string, error) {
	var c Claims

	token, err := goJwt.ParseWithClaims(t, &c, jwtKeyFunc)
	if err != nil {
		err = errors.Wrap(err, "Error while parsing token")
		return Claims{}, "", err
	}

	if time.Now().After(time.Unix(c.ExpirationUTC, 0)) || !token.Valid {
		return Claims{}, messages.Str("expiredToken"), nil
	}

	if tokenType != c.TokenType {
		return Claims{}, messages.Str("invalidToken"), nil
	}

	return c, "", nil
}

// RefreshTokens creates new access and refresh using old refresh token.
func RefreshTokens(t string) (string, string, string, error) {
	claims, msg, err := Valid(t, typeRefresh)
	if err != nil || msg != "" {
		err = errors.Wrap(err, "Error while validating token")
		return "", "", msg, err
	}

	access, refresh, err := AccessAndRefresh(claims.UserIdentity, claims.Scopes)
	err = errors.Wrap(err, "Error while creating access and refresh token")
	return access, refresh, "", err
}
