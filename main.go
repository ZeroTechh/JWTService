package main

import (
	"go.uber.org/zap"

	"github.com/ZeroTechh/VelocityCore/logger"
	proto "github.com/ZeroTechh/VelocityCore/proto/JWTService"
	"github.com/ZeroTechh/VelocityCore/services"
	"github.com/ZeroTechh/VelocityCore/utils"
	"github.com/ZeroTechh/hades"

	"github.com/ZeroTechh/JWTService/serviceHandler"
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
	defer log.Info("Service Stopped")

	grpcServer, listner := utils.CreateGRPCServer(
		services.JWTService,
		log,
	)

	serviceHandler := serviceHandler.Handler{}
	serviceHandler.Init()

	proto.RegisterJWTServer(grpcServer, serviceHandler)

	log.Info("Service Started")
	if err := grpcServer.Serve(*listner); err != nil {
		log.Fatal("Service Failed With Error", zap.Error(err))
	}
}
