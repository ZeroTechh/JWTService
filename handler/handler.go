package handler

import (
	"context"
	"strings"

	proto "github.com/ZeroTechh/VelocityCore/proto/JWTService"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"

	"github.com/ZeroTechh/JWTService/core/jwt"
)

// Handler handles all jwt service functions.
type Handler struct{}

// FreshToken creates fresh token.
func (Handler) FreshToken(ctx context.Context, request *proto.JWTData) (*proto.Token, error) {
	token, err := jwt.Fresh(request.UserIdentity)
	err = errors.Wrap(err, "Error while creating fresh token")
	return &proto.Token{Token: token}, err
}

// AccessAndRefreshTokens creates access and refresh tokens.
func (Handler) AccessAndRefreshTokens(ctx context.Context, request *proto.JWTData) (*proto.AccessAndRefreshToken, error) {
	access, refresh, err := jwt.AccessAndRefresh(
		request.UserIdentity,
		request.Scopes,
	)

	return &proto.AccessAndRefreshToken{
		AcccessToken: access,
		RefreshToken: refresh,
	}, errors.Wrap(err, "Error while creating access and refresh tokens")
}

// RefreshTokens creates access and refresh token based on old refresh token.
func (Handler) RefreshTokens(ctx context.Context, request *proto.Token) (*proto.AccessAndRefreshToken, error) {
	access, refresh, msg, err := jwt.RefreshTokens(request.Token)
	return &proto.AccessAndRefreshToken{
		AcccessToken: access,
		RefreshToken: refresh,
		Message:      msg,
	}, errors.Wrap(err, "Error while refreshing token")
}

// ValidateToken validates a token.
func (Handler) ValidateToken(ctx context.Context, request *proto.ValidRequest) (*proto.Claims, error) {
	tokenType := request.Type.String()
	claims, msg, err := jwt.Valid(request.Token, strings.ToLower(tokenType))
	if err != nil {
		return &proto.Claims{}, errors.Wrap(err, "Error while validating")
	}

	response := &proto.Claims{Message: msg}
	err = copier.Copy(&response, &claims)
	return response, errors.Wrap(err, "Error while copying")
}
