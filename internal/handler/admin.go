package handler

import (
	"mirea-qr/internal/model"
	"mirea-qr/internal/usecase"

	"github.com/gofiber/fiber/v3"
	"github.com/sirupsen/logrus"
)

type AdminController struct {
	Log     *logrus.Logger
	UseCase *usecase.AdminUseCase
}

func NewAdminController(useCase *usecase.AdminUseCase, logger *logrus.Logger) *AdminController {
	return &AdminController{
		Log:     logger,
		UseCase: useCase,
	}
}

func (c *AdminController) GetStats(ctx fiber.Ctx) error {
	response, err := c.UseCase.GetStats(ctx.Context())
	if err != nil {
		c.Log.Warnf("Failed to get admin stats : %+v", err)
		return err
	}

	return ctx.JSON(model.WebResponse[*model.AdminStatsResponse]{Data: response})
}
