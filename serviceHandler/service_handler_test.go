package serviceHandler

import (
	"context"
	"testing"

	proto "github.com/ZeroTechh/VelocityCore/proto/JWTService"
	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {
	assert := assert.New(t)
	handler := Handler{}
	handler.Init()
	ctx := context.TODO()
	id := "test"
	scopes := []string{"read", "write"}

	// Checking Generation Of Fresh Token
	freshTokenResp, err := handler.FreshToken(
		ctx,
		&proto.JWTData{
			UserIdentity: id,
			Scopes:       scopes,
		},
	)
	assert.NoError(err)
	assert.NotZero(freshTokenResp.Token)
	assert.Zero(freshTokenResp.Message)

	// Checking Generation Of Access And Refresh Token
	accessAndRefresh, err := handler.AccessAndRefreshTokens(
		ctx,
		&proto.JWTData{
			UserIdentity: id,
			Scopes:       scopes,
		},
	)
	assert.NoError(err)
	assert.NotZero(accessAndRefresh.AcccessToken)
	assert.NotZero(accessAndRefresh.RefreshToken)
	assert.Zero(accessAndRefresh.Message)

	// Checking Refreshing Of Tokens
	accessAndRefresh, err = handler.RefreshTokens(
		ctx,
		&proto.Token{
			Token: accessAndRefresh.RefreshToken,
		},
	)
	assert.NoError(err)
	assert.NotZero(accessAndRefresh.AcccessToken)
	assert.NotZero(accessAndRefresh.RefreshToken)
	assert.Zero(accessAndRefresh.Message)

	// Checking Validation Of Token
	claims, err := handler.ValidateToken(
		ctx,
		&proto.Token{
			Token: accessAndRefresh.RefreshToken,
		},
	)
	assert.NoError(err)
	assert.True(claims.Valid)
	assert.Equal(claims.TokenType, "refresh")

	// Checking If ValidateToken Can Detect Invalid Token
	claims, err = handler.ValidateToken(
		ctx,
		&proto.Token{
			Token: "invalidToken",
		},
	)
	assert.Error(err)

	// Checking If Refresh Token Can Detect False Token
	accessAndRefresh, err = handler.RefreshTokens(
		ctx,
		&proto.Token{
			Token: "invalidToken",
		},
	)
	assert.Error(err)
	assert.Zero(accessAndRefresh.AcccessToken)
	assert.Zero(accessAndRefresh.RefreshToken)
	assert.Zero(accessAndRefresh.Message)
}
