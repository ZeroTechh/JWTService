package main

import (
	"go.uber.org/zap"

	"github.com/ZeroTechh/JWTService/handler"
	"github.com/ZeroTechh/VelocityCore/logger"
	proto "github.com/ZeroTechh/VelocityCore/proto/JWTService"
	"github.com/ZeroTechh/VelocityCore/services"
	"github.com/ZeroTechh/VelocityCore/utils"
	"github.com/ZeroTechh/hades"
)

var (
	config = hades.GetConfig("main.yaml", []string{"config"})
	log    = logger.GetLogger(
		config.Map("service").Str("logFile"),
		config.Map("service").Bool("debug"),
	)
)

func main() {
	defer utils.HandlePanic(log)
	grpcServer, listner := utils.CreateGRPCServer(
		services.JWTService,
		log,
	)
	proto.RegisterJWTServer(grpcServer, handler.Handler{})
	if err := grpcServer.Serve(*listner); err != nil {
		log.Fatal("Service Failed With Error", zap.Error(err))
	}
}
