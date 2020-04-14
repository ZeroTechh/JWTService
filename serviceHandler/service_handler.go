package serviceHandler

import (
	"context"

	proto "github.com/ZeroTechh/VelocityCore/proto/JWTService"
	"github.com/jinzhu/copier"

	"github.com/ZeroTechh/JWTService/core/jwt"
)

// Handler is used to handle all jwt service functions
type Handler struct {
	jwt jwt.JWT
}

// Init is used to initialize
func (handler *Handler) Init() {
	handler.jwt = jwt.JWT{}
}

// FreshToken is used to generate fresh token
func (handler Handler) FreshToken(
	ctx context.Context,
	request *proto.JWTData) (*proto.Token, error) {
	token := handler.jwt.FreshToken(request.UserIdentity)
	return &proto.Token{Token: token}, nil
}

// AccessAndRefreshTokens is used to generate access and refresh tokens
func (handler Handler) AccessAndRefreshTokens(
	ctx context.Context,
	request *proto.JWTData) (*proto.AccessAndRefreshToken, error) {

	access, refresh := handler.jwt.AccessAndRefreshTokens(
		request.UserIdentity,
		request.Scopes,
	)

	return &proto.AccessAndRefreshToken{
		AcccessToken: access,
		RefreshToken: refresh,
	}, nil
}

// RefreshTokens is used to make access and refresh token based on refresh token
func (handler Handler) RefreshTokens(
	ctx context.Context,
	request *proto.Token) (*proto.AccessAndRefreshToken, error) {

	accessToken, refreshToken, msg, err := handler.jwt.RefreshTokens(
		request.Token,
	)
	if err != nil {
		return &proto.AccessAndRefreshToken{}, err
	}

	return &proto.AccessAndRefreshToken{
		AcccessToken: accessToken,
		RefreshToken: refreshToken,
		Message:      msg,
	}, nil
}

// ValidateToken is used to validate a token
func (handler Handler) ValidateToken(
	ctx context.Context,
	request *proto.Token) (response *proto.Claims, err error) {
	valid, claims, msg, err := handler.jwt.ValidateToken(request.Token)
	if err != nil {
		return
	}

	response = &proto.Claims{Message: msg, Valid: valid}
	copier.Copy(&response, &claims)
	return
}
