package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mirea-qr/internal/config"
	entity "mirea-qr/internal/entity"
	"mirea-qr/internal/model"
	"mirea-qr/internal/model/converter"
	"mirea-qr/internal/repository"
	"mirea-qr/pkg/crypto"
	"mirea-qr/pkg/customerrors"
	"mirea-qr/pkg/mirea"
	"sort"
	"strconv"
	"strings"
	"time"

	browser "github.com/EDDYCJY/fake-useragent"
	"github.com/go-playground/validator/v10"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type UserUseCase struct {
	Config             *config.Config
	DB                 *gorm.DB
	Log                *logrus.Logger
	Validate           *validator.Validate
	UserRepository     *repository.UserRepository
	LinkUserRepository *repository.LinkUserRepository
	Redis              *redis.Client
	Bot                *tgbotapi.BotAPI
	Encryptor          *crypto.Encryptor
}

func NewUserUseCase(cfg *config.Config, db *gorm.DB, logger *logrus.Logger, validate *validator.Validate, userRepository *repository.UserRepository, linkUserRepository *repository.LinkUserRepository, redis *redis.Client, bot *tgbotapi.BotAPI, encryptor *crypto.Encryptor) *UserUseCase {
	return &UserUseCase{
		Config:             cfg,
		DB:                 db,
		Log:                logger,
		Validate:           validate,
		UserRepository:     userRepository,
		LinkUserRepository: linkUserRepository,
		Redis:              redis,
		Bot:                bot,
		Encryptor:          encryptor,
	}
}

// createUserWithDecryptedPassword creates a user with decrypted password for API authorization
func (c *UserUseCase) createUserWithDecryptedPassword(user entity.User) (entity.User, error) {
	// Decrypt password
	decryptedPassword, err := c.Encryptor.Decrypt(user.Password)
	if err != nil {
		c.Log.Errorf("Failed to decrypt password for user %s: %+v", user.Email, err)
		return user, fiber.NewError(500, "Failed to decrypt password")
	}

	// Create user with decrypted password
	userWithDecryptedPassword := user
	userWithDecryptedPassword.Password = decryptedPassword

	return userWithDecryptedPassword, nil
}

const otpPendingTTL = 20 * time.Minute
const otpPendingKeyPrefix = "otp_pending:"

func otpPendingKey(telegramHash string, telegramId int64) string {
	if telegramHash != "" {
		return otpPendingKeyPrefix + telegramHash
	}
	return otpPendingKeyPrefix + "id:" + strconv.FormatInt(telegramId, 10)
}

func (c *UserUseCase) Create(ctx context.Context, request *model.RegisterUserRequest) (*model.UserResponse, *model.OtpRequiredResponse, error) {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return nil, nil, fiber.ErrBadRequest
	}

	// Проверяем, не зарегистрирован ли уже пользователь с таким Telegram ID
	user := new(entity.User)
	if err := c.UserRepository.FindByEmail(tx, user, request.Email); err == nil {
		c.Log.Warnf("User already exists with email %s : %+v", request.Email, err)
		//return nil, fiber.NewError(409, "В боте можно зарегистрироваться только с одного аккаунта Telegram")
	}

	attendance := mirea.NewAttendance(c.Config, entity.User{
		Email:    request.Email,
		Password: request.Password,
	}, c.Redis)

	encryptedPassword, err := c.Encryptor.Encrypt(request.Password)
	if err != nil {
		c.Log.Errorf("Failed to encrypt password: %+v", err)
		return nil, nil, fiber.ErrInternalServerError
	}

	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Authorization error : %+v", err)

		var authErr *customerrors.AuthError
		if errors.As(err, &authErr) {
			switch authErr.Type {
			case "invalid_credentials":
				return nil, nil, fiber.NewError(403, "Неверный логин или пароль от MIREA")
			case "network_error":
				return nil, nil, fiber.NewError(503, "Сайт MIREA не отвечает")
			case "site_unavailable":
				return nil, nil, fiber.NewError(503, "Сайт MIREA недоступен")
			case "totp_secret_required":
				return nil, nil, fiber.NewError(400, authErr.Message)
			case "otp_is_required":
				loginActionURL := authErr.GetLoginActionUrl()
				if loginActionURL == "" {
					return nil, nil, fiber.NewError(500, "Ошибка: ссылка авторизации не получена")
				}

				otpType := authErr.GetOtpType()
				key := otpPendingKey(request.TelegramHash, request.TelegramId)
				pending := model.OtpPendingData{
					TelegramId:     request.TelegramId,
					Email:          request.Email,
					Password:       encryptedPassword,
					LoginActionURL: loginActionURL,
					OtpType:        otpType,
				}
				if err := c.savePendingOtp(ctx, key, &pending); err != nil {
					c.Log.Errorf("Failed to save otp pending to Redis: %+v", err)
					return nil, nil, fiber.ErrInternalServerError
				}
				hashForFront := request.TelegramHash
				if hashForFront == "" {
					hashForFront = strconv.FormatInt(request.TelegramId, 10)
				}
				return nil, &model.OtpRequiredResponse{OtpRequired: true, TelegramHash: hashForFront, OtpType: otpType}, nil
			default:
				return nil, nil, fiber.NewError(500, "Ошибка авторизации в системе MIREA")
			}
		}
		return nil, nil, fiber.NewError(500, "Ошибка авторизации в системе MIREA")
	}

	student, err := attendance.GetMeInfo()
	if err != nil {
		c.Log.Errorf("Failed get me info : %+v", err)
		return nil, nil, fiber.ErrInternalServerError
	}

	group, err := attendance.GetAvailableGroup()
	if err != nil {
		c.Log.Errorf("Failed get group : %+v", err)
		return nil, nil, fiber.ErrInternalServerError
	}

	fullname := strings.Join([]string{student.GetFullname(), student.GetName(), student.GetMiddlename().GetValue()}, " ")
	if user.ID != "" {
		user.TelegramId = request.TelegramId
		user.Group = group.Title
		user.GroupID = group.UUID
		if err := c.UserRepository.Update(tx, user); err != nil {
			c.Log.Warnf("Failed update user to database : %+v", err)
			return nil, nil, fiber.NewError(500, err.Error())
		}
	} else {
		user = &entity.User{
			ID:         student.Id,
			TelegramId: request.TelegramId,
			Email:      strings.ToLower(request.Email),
			Password:   encryptedPassword,
			Fullname:   fullname,
			Group:      group.Title,
			GroupID:    group.UUID,
			UserAgent:  browser.Mobile(),
		}

		if err := c.UserRepository.Create(tx, user); err != nil {
			c.Log.Warnf("Failed create user to database : %+v", err)
			return nil, nil, fiber.NewError(500, err.Error())
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return nil, nil, fiber.ErrInternalServerError
	}

	return converter.UserToResponse(user), nil, nil
}

func (c *UserUseCase) savePendingOtp(ctx context.Context, key string, pending *model.OtpPendingData) error {
	data, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	return c.Redis.Set(ctx, key, data, otpPendingTTL).Err()
}

// SubmitOtp завершает регистрацию после ввода OTP: находит данные в Redis, отправляет код по ссылке, создаёт пользователя.
func (c *UserUseCase) SubmitOtp(ctx context.Context, request *model.SubmitOtpRequest) (*model.UserResponse, error) {
	if request.TelegramHash == "" {
		return nil, fiber.NewError(400, "telegram_hash обязателен")
	}
	var key string
	allDigits := true
	for _, r := range request.TelegramHash {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		key = otpPendingKeyPrefix + "id:" + request.TelegramHash
	} else {
		key = otpPendingKeyPrefix + request.TelegramHash
	}
	data, err := c.Redis.Get(ctx, key).Bytes()
	if err != nil {
		c.Log.Warnf("Otp pending not found or expired: %+v", err)
		return nil, fiber.NewError(404, "Сессия истекла или не найдена. Повторите вход.")
	}
	var pending model.OtpPendingData
	if err := json.Unmarshal(data, &pending); err != nil {
		c.Log.Warnf("Invalid otp pending data: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	attendance := mirea.NewAttendance(c.Config, entity.User{
		Email: pending.Email,
	}, c.Redis)
	attendance.SetUseCase(false)
	otpType := pending.OtpType
	if otpType == "" {
		otpType = "email"
	}

	if err := attendance.HandleTwoFactorAuth(pending.LoginActionURL, request.OtpCode, otpType); err != nil {
		var authErr *customerrors.AuthError
		if errors.As(err, &authErr) && authErr.Type == "otp_code_is_wrong" {
			loginActionURL := authErr.GetLoginActionUrl()
			otpTypeFromErr := authErr.GetOtpType()
			if loginActionURL != "" {
				pending.LoginActionURL = loginActionURL
				pending.OtpType = otpTypeFromErr
				_ = c.savePendingOtp(ctx, key, &pending)
			}
			return nil, fiber.NewError(400, "Неверный код OTP")
		}
		c.Log.Warnf("HandleTwoFactorAuth error: %+v", err)
		return nil, fiber.NewError(400, err.Error())
	}

	student, err := attendance.GetMeInfo()
	if err != nil {
		c.Log.Errorf("Failed get me info after OTP: %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	group, err := attendance.GetAvailableGroup()
	if err != nil {
		c.Log.Errorf("Failed get group after OTP: %+v", err)
		return nil, fiber.ErrInternalServerError
	}

	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	fullname := strings.Join([]string{student.GetFullname(), student.GetName(), student.GetMiddlename().GetValue()}, " ")

	existingUser := new(entity.User)
	if err := c.UserRepository.FindByEmail(tx, existingUser, pending.Email); err == nil {
		existingUser.TelegramId = pending.TelegramId
		existingUser.Group = group.Title
		existingUser.GroupID = group.UUID
		if err := c.UserRepository.Update(tx, existingUser); err != nil {
			c.Log.Warnf("Failed update user: %+v", err)
			return nil, fiber.ErrInternalServerError
		}
		if err := tx.Commit().Error; err != nil {
			return nil, fiber.ErrInternalServerError
		}
		_ = c.Redis.Del(ctx, key)
		return converter.UserToResponse(existingUser), nil
	}

	newUser := &entity.User{
		ID:         student.Id,
		TelegramId: pending.TelegramId,
		Email:      strings.ToLower(pending.Email),
		Password:   pending.Password,
		Fullname:   fullname,
		Group:      group.Title,
		GroupID:    group.UUID,
		UserAgent:  browser.Mobile(),
	}
	if err := c.UserRepository.Create(tx, newUser); err != nil {
		c.Log.Warnf("Failed create user: %+v", err)
		return nil, fiber.ErrInternalServerError
	}
	if err := tx.Commit().Error; err != nil {
		return nil, fiber.ErrInternalServerError
	}
	_ = c.Redis.Del(ctx, key)
	return converter.UserToResponse(newUser), nil
}

func (c *UserUseCase) UpdateDataForUser(user *entity.User) error {
	tx := c.DB.WithContext(context.Background()).Begin()
	defer tx.Rollback()

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(*user)
	if err != nil {
		return errors.New("failed to decrypt password")
	}

	attendance := mirea.NewAttendance(c.Config, userWithDecryptedPassword, c.Redis)
	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Wrong login or password from mirea : %+v", err)
		return errors.New("wrong login or password")
	}

	student, err := attendance.GetMeInfo()
	if err != nil {
		return errors.New("failed get me info")
	}

	group, err := attendance.GetAvailableGroup()
	if err != nil {
		return errors.New("failed get group")
	}

	var middlename string
	if student.GetMiddlename() != nil {
		middlename = student.GetMiddlename().GetValue()
	}
	user.Fullname = strings.Join([]string{student.GetFullname(), student.GetName(), middlename}, " ")
	user.Group = group.Title
	user.GroupID = group.UUID

	if err := c.UserRepository.Update(tx, user); err != nil {
		return errors.New("failed update user")
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return errors.New("failed commit")
	}

	return nil
}

func (c *UserUseCase) ConnectStudent(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &fromUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var toUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &toUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	if fromUser.ID == toUser.ID {
		return fiber.NewError(400, "Вы не можете подключить самого себя")
	}

	var linkUserAlready entity.LinkUser
	if err := c.LinkUserRepository.FindLinkUser(tx, &linkUserAlready, fromUser.ID, toUser.ID); err == nil && linkUserAlready.FromUserID != "" {
		c.Log.Warnf("Link user already exists : %+v", linkUserAlready)
		return fiber.NewError(400, "Пользователь уже подключен")
	}

	linkUser := entity.LinkUser{
		FromUserID: fromUser.ID,
		ToUserID:   toUser.ID,
		Enabled:    true,
	}
	if err := c.LinkUserRepository.Create(tx, &linkUser); err != nil {
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	if c.Bot != nil {
		c.Bot.Send(tgbotapi.NewMessage(toUser.TelegramId, fmt.Sprintf("Вы были подключены к %s", fromUser.Fullname)))
	}

	return nil
}

func (c *UserUseCase) ChangeEnabledConnectedStudent(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &fromUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var toUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &toUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	var linkUser entity.LinkUser
	if err := c.LinkUserRepository.FindLinkUser(tx, &linkUser, fromUser.ID, toUser.ID); err != nil {
		return fiber.ErrNotFound
	}

	c.Log.Warnf("Link user : %+v", linkUser)
	linkUser.Enabled = !linkUser.Enabled

	if err := c.LinkUserRepository.UpdateLinkUser(tx, &linkUser); err != nil {
		c.Log.Warnf("Failed update link user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) DisconnectStudent(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &fromUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var toUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &toUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	if err := c.LinkUserRepository.DeleteLinkUser(tx, fromUser.ID, toUser.ID); err != nil {
		c.Log.Warnf("Failed to delete link user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) DisconnectFromUser(ctx context.Context, request *model.ConnectStudentRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var toUser entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &toUser, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	var fromUser entity.User
	if err := c.UserRepository.FindByEmail(tx, &fromUser, request.Email); err != nil {
		return fiber.ErrNotFound
	}

	if err := c.LinkUserRepository.DeleteLinkUser(tx, fromUser.ID, toUser.ID); err != nil {
		c.Log.Warnf("Failed to delete link user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) ChangePassword(ctx context.Context, request *model.ChangePasswordRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var user entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &user, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	// Проверяем новый пароль
	user.Password = request.NewPassword

	newAttendance := mirea.NewAttendance(c.Config, user, c.Redis)
	newAttendance.SetUseCase(false)
	if err := newAttendance.Authorization(); err != nil {
		c.Log.Warnf("Wrong new password : %+v", err)
		return fiber.NewError(403, "Неверный новый пароль")
	}

	// Encrypt new password before saving
	encryptedPassword, err := c.Encryptor.Encrypt(request.NewPassword)
	if err != nil {
		c.Log.Errorf("Failed to encrypt new password: %+v", err)
		return fiber.ErrInternalServerError
	}

	// Обновляем пароль в базе данных
	user.Password = encryptedPassword
	if err := c.UserRepository.Update(tx, &user); err != nil {
		c.Log.Warnf("Failed update user password : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func getCourseByGroup(code string) int {
	parts := strings.Split(code, "-")
	if len(parts) < 3 {
		return 0
	}

	// последние две цифры
	lastPart := parts[len(parts)-1]

	yearSuffix, err := strconv.Atoi(lastPart)
	if err != nil {
		return 0
	}

	// формула
	value := (25 - yearSuffix) + 1

	return value
}

func getMoscowDayBounds() (int64, int64) {
	moscowLoc, _ := time.LoadLocation("Europe/Moscow")
	now := time.Now().In(moscowLoc)

	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, moscowLoc)
	endOfDay := time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, moscowLoc)

	return startOfDay.Unix(), endOfDay.Unix()
}

// getBuildingName преобразует код корпуса в читаемое название
func getBuildingName(locationTitle string) string {
	if locationTitle == "Неконтролируемая территория" {
		return "Улица"
	}

	// Берем только первое слово (код корпуса)
	parts := strings.Fields(locationTitle)
	if len(parts) == 0 {
		return locationTitle
	}

	code := parts[0]

	// Преобразуем известные коды корпусов
	switch code {
	case "С20":
		return "Стромынка"
	case "П1":
		return "Пироговка"
	case "В78":
		return "Вернадка"
	default:
		return code
	}
}

func (c *UserUseCase) GetUniversityStatus(ctx context.Context, user *entity.User) (*model.UniversityStatusResponse, error) {
	// Get user with decrypted password for authorization
	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(*user)
	if err != nil {
		c.Log.Errorf("Failed to decrypt password for user %s: %+v", user.Email, err)
		return nil, fiber.NewError(500, "Не удалось расшифровать пароль")
	}

	attendance := mirea.NewAttendance(c.Config, userWithDecryptedPassword, c.Redis)

	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Failed to authorize attendance : %+v", err)
		return nil, fiber.NewError(500, "Не удалось авторизоваться в системе посещаемости")
	}

	startTime, endTime := getMoscowDayBounds()

	events, err := attendance.GetHumanAcsEvents(startTime, endTime)
	if err != nil {
		c.Log.Errorf("Failed to get ACS events : %+v", err)
		if err != nil && err.Error() != "wrong base64" {
			return nil, fiber.NewError(500, "Не удалось получить данные о проходах")
		}
	}

	response := &model.UniversityStatusResponse{
		IsInUniversity: false,
		EntryTime:      0,
		ExitTime:       0,
		Events:         []model.UniversityEventDetail{},
	}

	if len(events) > 0 {
		sort.Slice(events, func(i, j int) bool {
			return events[i].GetTime().GetValue() < events[j].GetTime().GetValue()
		})

		response.EntryTime = events[0].GetTime().GetValue()

		// Создаем детальную информацию о событиях
		for i, event := range events {
			entryLocation := ""
			exitLocation := ""

			if event.GetEntryLocation() != nil {
				entryLocation = getBuildingName(event.GetEntryLocation().GetTitle())
			}
			if event.GetExitLocation() != nil {
				exitLocation = getBuildingName(event.GetExitLocation().GetTitle())
			}

			// Определяем, является ли событие входом или выходом
			// Если это первое событие или предыдущее событие было выходом, то это вход
			isEntry := i == 0
			if i > 0 {
				prevEvent := events[i-1]
				prevIsExit := false
				if prevEvent.GetExitLocation() != nil && prevEvent.GetExitLocation().GetTitle() != "Неконтролируемая территория" {
					prevIsExit = true
				}
				isEntry = prevIsExit
			}

			response.Events = append(response.Events, model.UniversityEventDetail{
				Time:          event.GetTime().GetValue(),
				EntryLocation: entryLocation,
				ExitLocation:  exitLocation,
				IsEntry:       isEntry,
			})
		}

		// Определяем, находится ли студент в университете
		// Возможные значение GetTitle()
		// С20 1эт ЦентральныйВход
		// С20 КПП2
		// П1 А 1эт ЦентральныйВход ДополнительныйВход
		// и т.д
		if events[len(events)-1].GetExitLocation().GetTitle() != "Неконтролируемая территория" {
			response.IsInUniversity = false
			response.ExitTime = events[len(events)-1].GetTime().GetValue()
		} else {
			response.IsInUniversity = true
		}
	}

	return response, nil
}

func (c *UserUseCase) DeleteUser(ctx context.Context, user *entity.User) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	if err := c.LinkUserRepository.DeleteByFromUser(tx, user.ID); err != nil {
		c.Log.Warnf("Failed to delete user connections as from_user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := c.LinkUserRepository.DeleteByToUser(tx, user.ID); err != nil {
		c.Log.Warnf("Failed to delete user connections as to_user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := c.UserRepository.Delete(tx, user); err != nil {
		c.Log.Warnf("Failed to delete user : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) UpdateProxy(ctx context.Context, request *model.UpdateProxyRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var user entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &user, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	user.CustomProxy = request.Proxy
	if err := c.UserRepository.Update(tx, &user); err != nil {
		c.Log.Warnf("Failed update user proxy : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}

func (c *UserUseCase) UpdateTotpSecret(ctx context.Context, request *model.UpdateTotpSecretRequest) error {
	tx := c.DB.WithContext(ctx).Begin()
	defer tx.Rollback()

	err := c.Validate.Struct(request)
	if err != nil {
		c.Log.Warnf("Invalid request body : %+v", err)
		return fiber.ErrBadRequest
	}

	var user entity.User
	if err := c.UserRepository.FindByTelegramID(tx, &user, request.TelegramId); err != nil {
		return fiber.ErrNotFound
	}

	if user.Email == "" || user.Password == "" {
		c.Log.Warnf("User %d does not have email or password for authorization check", request.TelegramId)
		return fiber.NewError(400, "Для проверки TOTP secret требуется email и пароль пользователя")
	}

	userWithDecryptedPassword, err := c.createUserWithDecryptedPassword(user)
	if err != nil {
		c.Log.Warnf("Failed to decrypt password for user %d: %+v", request.TelegramId, err)
		return fiber.ErrInternalServerError
	}

	testUser := userWithDecryptedPassword
	testUser.TotpSecret = request.TotpSecret
	attendance := mirea.NewAttendance(c.Config, testUser, c.Redis)
	attendance.SetUseCase(false)

	if err := attendance.Authorization(); err != nil {
		c.Log.Warnf("Authorization check failed with new TOTP secret for user %d: %+v", request.TelegramId, err)

		var authErr *customerrors.AuthError
		if errors.As(err, &authErr) {
			switch authErr.Type {
			case "invalid_credentials":
				return fiber.NewError(403, "Неверный TOTP secret. Проверьте правильность ввода")
			case "totp_secret_required":
				return fiber.NewError(400, authErr.Message)
			case "network_error":
				return fiber.NewError(503, "Сайт MIREA не отвечает. Попробуйте позже")
			case "site_unavailable":
				return fiber.NewError(503, "Сайт MIREA недоступен. Попробуйте позже")
			default:
				return fiber.NewError(500, "Ошибка проверки авторизации: "+authErr.Message)
			}
		}

		return fiber.NewError(500, "Ошибка проверки авторизации с новым secret")
	}

	user.TotpSecret = request.TotpSecret
	if err := c.UserRepository.Update(tx, &user); err != nil {
		c.Log.Warnf("Failed update user totp secret : %+v", err)
		return fiber.ErrInternalServerError
	}

	if err := tx.Commit().Error; err != nil {
		c.Log.Warnf("Failed commit transaction : %+v", err)
		return fiber.ErrInternalServerError
	}

	return nil
}
