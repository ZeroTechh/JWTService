package main

import (
	"go.uber.org/zap"

	"github.com/ZeroTechh/VelocityCentral/logger"
	proto "github.com/ZeroTechh/VelocityCentral/proto/JWTService"
	"github.com/ZeroTechh/VelocityCentral/services"
	"github.com/ZeroTechh/VelocityCentral/utils"
	"github.com/ZeroTechh/hades"

	"github.com/ZeroTechh/JWTService/handler"
)

var config = hades.GetConfig("main.yaml", []string{"config"})
var log = logger.GetLogger(
	config.Map("service").Str("logFile"),
	config.Map("service").Bool("debug"),
)

func main() {

	defer utils.HandlePanic(log)

	grpcServer, listner := utils.CreateGRPCServer(
		services.JWTService,
		log,
	)

	serviceHandler := handler.Handler{}
	serviceHandler.Init()

	proto.RegisterJWTServer(grpcServer, serviceHandler)

	if err := grpcServer.Serve(*listner); err != nil {
		log.Fatal("Service Failed With Error", zap.Error(err))
	}
}
