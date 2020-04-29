package handler

import (
	"context"
	"testing"

	proto "github.com/ZeroTechh/VelocityCore/proto/JWTService"
	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {
	assert := assert.New(t)
	handler := Handler{}
	ctx := context.TODO()
	id := "test"
	scopes := []string{"read", "write"}

	// Testing FreshTokens.
	fresh, err := handler.FreshToken(ctx, &proto.JWTData{
		UserIdentity: id, Scopes: scopes,
	})
	assert.NoError(err)
	assert.NotZero(fresh)

	// Testing AccessAndRefreshTokens.
	accessAndRefresh, err := handler.AccessAndRefreshTokens(ctx, &proto.JWTData{
		UserIdentity: id, Scopes: scopes,
	})
	assert.NotZero(accessAndRefresh)
	assert.NoError(err)

	// Testing RefreshTokens.
	accessAndRefresh, err = handler.RefreshTokens(ctx, &proto.Token{
		Token: accessAndRefresh.RefreshToken,
	})
	assert.NotZero(accessAndRefresh)
	assert.NoError(err)

	// Testing ValidateToken.
	valid, err := handler.ValidateToken(ctx, &proto.ValidRequest{
		Token: accessAndRefresh.AcccessToken,
		Type:  proto.TokenType_ACCESS,
	})
	assert.NotZero(valid)
	assert.NoError(err)

	// Testing ValidateToken returns error for invalid token.
	valid, err = handler.ValidateToken(ctx, &proto.ValidRequest{
		Token: "invalid",
		Type:  proto.TokenType_ACCESS,
	})
	assert.Zero(valid.UserIdentity)
	assert.Error(err)
}
