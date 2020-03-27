package jwt

import (
	"testing"
	"time"

	goJwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func createExpiredToken() string {
	accessClaims := accessTokenClaims("test", []string{"test"})
	accessClaims.ExpirationUTC = time.Now().Unix()
	accessToken := goJwt.NewWithClaims(goJwt.SigningMethodHS256, accessClaims)
	accessTokenString, _ := accessToken.SignedString(secret)
	return accessTokenString
}

func testToken(
	token,
	id string,
	scopes []string,
	expirationTime time.Duration,
	t *testing.T) {
	assert := assert.New(t)
	jwt := JWT{}

	valid, claims, msg, err := jwt.ValidateToken(token)
	assert.NoError(err)
	assert.Zero(msg)
	assert.NotNil(claims)
	assert.True(valid)

	assert.WithinDuration(
		time.Now(),
		time.Unix(claims.CreationUTC, 0),
		time.Second,
	)

	assert.WithinDuration(
		time.Now().Add(expirationTime),
		time.Unix(claims.ExpirationUTC, 0),
		time.Second,
	)

	assert.Equal(scopes, claims.Scopes)
}

func testAccessAndRefresh(access, refresh, id string, scopes []string, t *testing.T) {
	testToken(
		access,
		id,
		scopes,
		time.Duration(expirations.Int("access"))*time.Minute,
		t,
	)

	testToken(
		refresh,
		id,
		scopes,
		time.Duration(expirations.Int("refresh"))*time.Minute,
		t,
	)
}

func TestClaimsGen(t *testing.T) {
	assert := assert.New(t)

	scopes := []string{"read", "write", "delete"}
	id := "testing"

	accessClaims := accessTokenClaims(id, scopes)
	assert.Equal(accessClaims.TokenType, typeAccess)

	refreshClaims := refreshTokenClaims(id, scopes)
	assert.Equal(refreshClaims.TokenType, typeRefresh)

	freshClaims := freshTokenClaims(id)
	assert.Equal(freshClaims.TokenType, typeFresh)
}

func TestJWT(t *testing.T) {
	assert := assert.New(t)
	jwt := JWT{}
	scopes := []string{"read", "write", "delete"}
	id := "testing"

	// Testing access and refresh token generation
	accessToken, refreshToken := jwt.AccessAndRefreshTokens(id, scopes)
	testAccessAndRefresh(accessToken, refreshToken, id, scopes, t)

	// Testing Refreshing Of Token
	accessToken, refreshToken, msg, err := jwt.RefreshTokens(refreshToken)
	testAccessAndRefresh(accessToken, refreshToken, id, scopes, t)
	assert.Zero(msg)
	assert.NoError(err)

	// Checking If RefreshTokens Can Detect Invalid Token
	_, _, msg, err = jwt.RefreshTokens("invalidToken")
	assert.Zero(msg)
	assert.Error(err)

	// Tesing Fresh Token Generation
	fresh := jwt.FreshToken(id)
	testToken(
		fresh,
		id,
		nil,
		time.Duration(expirations.Int(typeFresh))*time.Minute,
		t,
	)

	accessToken, _ = jwt.AccessAndRefreshTokens("test", nil)
	accessToken, refreshToken, msg, err = jwt.RefreshTokens(accessToken)
	assert.NoError(err)
	assert.Zero(accessToken)
	assert.Zero(refreshToken)
	assert.NotNil(msg)

	// Checking If Validate Token Can Detect Invalid Token
	valid, claims, msg, err := jwt.ValidateToken("InvalidToken")
	assert.False(valid)
	assert.Zero(claims)
	assert.Zero(msg)
	assert.Error(err)

	// Checking if ValidateToken Can Detect Expired Token
	expiredAccessToken := createExpiredToken()
	valid, claims, msg, err = jwt.ValidateToken(expiredAccessToken)
	assert.False(valid)
	assert.Zero(claims)
	assert.Equal(messages.Str("expiredToken"), msg)
	assert.NoError(err)

	// Checking If Parser Can Detect Invalid Access Token
	invalidAccessToken := "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MqF1AKsJkijKnfqEI3VA1OnzAL2S4eIpAuievMgD3tEFyFMU67gCbg-fxsc5dLrxNwdZEXs9h0kkicJZ70mp6p5vdv-j2ycDKBWg05Un4OhEl7lYcdIsCsB8QUPmstF-lQWnNqnq3wra1GynJrOXDL27qIaJnnQKlXuayFntBF0j-82jpuVdMaSXvk3OGaOM-7rCRsBcSPmocaAO-uWJEGPw_OWVaC5RRdWDroPi4YL4lTkDEC-KEvVkqCnFm_40C-T_siXquh5FVbpJjb3W2_YvcqfDRj44TsRrpVhk6ohsHMNeUad_cxnFnpolIKnaXq_COv35e9EgeQIPAbgIeg"
	_, err = goJwt.ParseWithClaims(invalidAccessToken, &claims, jwtKeyFunc)
	assert.Error(err)
}
