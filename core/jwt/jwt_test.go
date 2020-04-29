package jwt

import (
	"testing"
	"time"

	goJwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestJWT(t *testing.T) {
	assert := assert.New(t)
	scopes := []string{"read", "write", "delete"}
	id := "testing"

	// Testing AccessAndRefresh.
	access, refresh, err := AccessAndRefresh(id, scopes)
	assert.NotZero(access)
	assert.NotZero(refresh)
	assert.NoError(err)

	// Testing RefreshTokens.
	access, refresh, msg, err := RefreshTokens(refresh)
	assert.NotZero(access)
	assert.NotZero(refresh)
	assert.Zero(msg)
	assert.NoError(err)

	// Checking RefreshTokens returns error for invalid token.
	_, _, _, err = RefreshTokens("invalidToken")
	assert.Error(err)

	// Checking Fresh
	fresh, err := Fresh(id)
	assert.NotZero(fresh)
	assert.NoError(err)

	// Testing Valid returns msg for expired token
	c := claims(id, scopes, typeAccess)
	c.ExpirationUTC = time.Now().Unix()
	access, _ = token(c)
	_, msg, _ = Valid(access, typeAccess)
	assert.NotZero(msg)

	// Testing Valid returns msg for different type of token
	_, msg, _ = Valid(fresh, typeAccess)
	assert.NotZero(msg)

	// Checking If Parser Can Detect Invalid Access Token
	invalid := "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MqF1AKsJkijKnfqEI3VA1OnzAL2S4eIpAuievMgD3tEFyFMU67gCbg-fxsc5dLrxNwdZEXs9h0kkicJZ70mp6p5vdv-j2ycDKBWg05Un4OhEl7lYcdIsCsB8QUPmstF-lQWnNqnq3wra1GynJrOXDL27qIaJnnQKlXuayFntBF0j-82jpuVdMaSXvk3OGaOM-7rCRsBcSPmocaAO-uWJEGPw_OWVaC5RRdWDroPi4YL4lTkDEC-KEvVkqCnFm_40C-T_siXquh5FVbpJjb3W2_YvcqfDRj44TsRrpVhk6ohsHMNeUad_cxnFnpolIKnaXq_COv35e9EgeQIPAbgIeg"
	_, err = goJwt.ParseWithClaims(invalid, &c, jwtKeyFunc)
	assert.Error(err)
}
