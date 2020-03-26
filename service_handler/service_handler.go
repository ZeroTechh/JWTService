package handler

import (
	"context"

	"github.com/ZeroTechh/VelocityCentral/logger"
	proto "github.com/ZeroTechh/VelocityCentral/proto/JWTService"
	"github.com/ZeroTechh/blaze"
	"github.com/ZeroTechh/hades"
	"github.com/jinzhu/copier"
	"go.uber.org/zap"

	"github.com/ZeroTechh/JWTService/jwt"
)

var (
	config = hades.GetConfig("main.yaml", []string{"config", "../config"})
	log    = logger.GetLogger(
		config.Map("service").Str("logFile"),
		config.Map("service").Bool("debug"),
	)
)

// to be executed when panic occurs
func panicHandlerFunc(msg interface{}, data ...interface{}) {
	funcLog := data[0].(*blaze.FuncLog)
	funcLog.Panic(msg)
}

// Handler is used to handle all jwt service functions
type Handler struct {
	jwt          jwt.JWT
	panicHandler *blaze.PanicHandler
}

// Init is used to initialize
func (handler *Handler) Init() {
	handler.jwt = jwt.JWT{}
	handler.panicHandler = blaze.NewPanicHandler(panicHandlerFunc)
}

// FreshToken is used to generate fresh token
func (handler Handler) FreshToken(
	ctx context.Context,
	request *proto.JWTData) (*proto.Token, error) {
	funcLog := blaze.NewFuncLog(
		"JWTService.Handler.FreshToken",
		log,
		zap.String("ID", request.UserIdentity),
	)

	defer handler.panicHandler.Check(funcLog)
	funcLog.Started()
	token := handler.jwt.FreshToken(request.UserIdentity)
	funcLog.Completed(zap.String("Token", token))

	return &proto.Token{Token: token}, nil
}

// AccessAndRefreshTokens is used to generate access and refresh tokens
func (handler Handler) AccessAndRefreshTokens(
	ctx context.Context,
	request *proto.JWTData) (*proto.AccessAndRefreshToken, error) {
	funcLog := blaze.NewFuncLog(
		"JWTService.Handler.AccessAndRefreshTokens",
		log,
		zap.String("ID", request.UserIdentity),
		zap.Strings("Scopes", request.Scopes),
	)
	defer handler.panicHandler.Check(funcLog)
	funcLog.Started()

	access, refresh := handler.jwt.AccessAndRefreshTokens(
		request.UserIdentity,
		request.Scopes,
	)

	funcLog.Completed(
		zap.String("AccessToken", access),
		zap.String("RefreshToken", refresh),
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
	funcLog := blaze.NewFuncLog(
		"JWTService.Handler.RefreshTokens",
		log,
		zap.String("Token", request.Token),
	)
	defer handler.panicHandler.Check(funcLog)
	funcLog.Started()

	accessToken, refreshToken, msg, err := handler.jwt.RefreshTokens(
		request.Token,
	)
	if err != nil {
		funcLog.Error(err)
		return &proto.AccessAndRefreshToken{}, err
	}

	funcLog.Completed(
		zap.String("AccessToken", accessToken),
		zap.String("RefreshToken", refreshToken),
		zap.String("Message", msg),
	)

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
	funcLog := blaze.NewFuncLog(
		"JWTService.Handler.ValidateToken",
		log,
		zap.String("Token", request.Token),
	)
	defer handler.panicHandler.Check(funcLog)
	funcLog.Started()

	valid, claims, msg, err := handler.jwt.ValidateToken(request.Token)
	if err != nil {
		funcLog.Error(err)
		return
	}

	response = &proto.Claims{Message: msg, Valid: valid}
	copier.Copy(&response, &claims)

	funcLog.Completed(
		zap.String("Message", msg),
		zap.Bool("Valid", valid),
	)
	return
}
