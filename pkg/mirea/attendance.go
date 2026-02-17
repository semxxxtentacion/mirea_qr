package mirea

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mirea-qr/internal/entity"
	"mirea-qr/pkg/customerrors"
	message "mirea-qr/pkg/mirea/proto"
	"mirea-qr/pkg/proxy"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"resty.dev/v3"
)

var proxyBlockedErr = errors.New("proxy blocked")

type Attendance struct {
	user         entity.User
	appVersion   string
	client       *resty.Client
	redis        *redis.Client
	useCache     bool
	currentProxy string
	retryCount   int
}

type RestySession struct {
	Cookies []*http.Cookie `json:"cookies"`
}

type GroupResponse struct {
	UUID  string
	Title string
}

func NewAttendance(user entity.User, redis *redis.Client) *Attendance {
	client := resty.New()

	client.SetHeader("User-Agent", user.UserAgent)
	client.SetTimeout(10 * time.Second)

	a := &Attendance{
		user:       user,
		appVersion: "1.6.0+5227", // TODO: automatic parse
		client:     client,
		redis:      redis,
		useCache:   true,
		retryCount: 0,
	}
	a.SetProxy()

	return a
}

func (a *Attendance) SetProxy() string {
	randProxy, err := proxy.GetUserProxy(a.user.CustomProxy, a.redis)
	if err != nil {
		log.Fatalf("failed load proxy : %+v", err)
	}
	a.client.SetProxy(randProxy)
	a.currentProxy = randProxy

	return randProxy
}

func (a *Attendance) SetUseCase(cache bool) {
	a.useCache = cache
}

func (a *Attendance) GetCurrentUser() entity.User {
	return a.user
}

// saveSessionToRedis сохраняет сессию в redis
func (a *Attendance) saveSessionToRedis() error {
	ctx := context.Background()
	u, _ := url.Parse("https://attendance.mirea.ru") // .AspNetCore.Cookies - по сути только это нужно
	cookies := a.client.CookieJar().Cookies(u)

	session := RestySession{
		Cookies: cookies,
	}

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	return a.redis.Set(ctx, a.getSessionKeyToRedis(), data, 7*24*time.Hour).Err()
}

// loadSessionFromRedis восстанавливает сессию из redis
func (a *Attendance) loadSessionFromRedis() error {
	ctx := context.Background()
	data, err := a.redis.Get(ctx, a.getSessionKeyToRedis()).Bytes()

	if err != nil {
		return err
	}

	var session RestySession
	if err := json.Unmarshal(data, &session); err != nil {
		return err
	}

	a.client.SetCookies(session.Cookies)
	return nil
}

// getSessionKeyToRedis возвращает ключ для сессии redis
func (a *Attendance) getSessionKeyToRedis() string {
	return "sess_" + a.user.Email
}

// Authorization выполняет авторизацию в attendance-app
func (a *Attendance) Authorization() error {
	if a.retryCount >= 3 {
		return customerrors.NewAuthError("network_error", "Сайт MIREA не отвечает", errors.New("network error"))
	}

	if a.useCache {
		if err := a.loadSessionFromRedis(); err == nil {
			info, err := a.GetMeInfo()
			if err != nil {
				if a.currentProxy != "" {
					_ = proxy.BlockProxy(a.redis, a.currentProxy, 30*time.Second)
				}
				a.retryCount++
				return a.Authorization()
			}
			if info != nil {
				return nil
			}
		}
	}

	if err := a.checkSiteAvailability(); err != nil {
		return err
	}

	resp, err := a.client.R().
		Get("https://attendance.mirea.ru/api/auth/login?redirectUri=https%3A%2F%2Fattendance-app.mirea.ru%2Fservices&rememberMe=True")
	if err != nil {
		if a.currentProxy != "" {
			_ = proxy.BlockProxy(a.redis, a.currentProxy, 30*time.Second)
		}
		a.retryCount++
		return a.Authorization()
	}

	loginActionURL, err := a.getLoginActionURL(resp.String())
	if err != nil {
		return err
	}

	loginResp, err := a.performLogin(loginActionURL)
	if err != nil {
		return err
	}

	redirects := loginResp.RedirectHistory()
	if len(redirects) == 0 {
		return customerrors.NewAuthError("invalid_credentials", "Неверный логин или пароль от MIREA", errors.New("not redirected after authorization"))
	}

	if redirects[0].URL != "https://attendance-app.mirea.ru/services" {
		if !strings.Contains(loginResp.String(), `"helpText": "otp-help-text"`) {
			return customerrors.NewAuthError("invalid_credentials", "Неверный логин или пароль от MIREA", errors.New("unexpected redirect, not two-factor auth"))
		}

		if err := a.handleTwoFactorAuth(loginResp); err != nil {
			return err
		}
	}

	group, err := a.GetAvailableGroup()
	if err != nil {
		return customerrors.NewAuthError("invalid_credentials", "Неверный логин или пароль от MIREA", errors.New("failed get group, because not authorized"))
	}
	a.user.GroupID = group.UUID

	if err := a.saveSessionToRedis(); err != nil {
		return customerrors.NewAuthError("internal_error", "Система кеша не отвечает", err)
	}

	return nil
}

// checkSiteAvailability проверяет доступность сайта MIREA
func (a *Attendance) checkSiteAvailability() error {
	if a.retryCount >= 3 {
		return customerrors.NewAuthError("network_error", "Сайт MIREA не отвечает", errors.New("network error"))
	}

	if _, err := a.client.R().Get("https://attendance-app.mirea.ru/"); err != nil {
		if a.currentProxy != "" {
			_ = proxy.BlockProxy(a.redis, a.currentProxy, 30*time.Second)
		}
		a.retryCount++
		return a.checkSiteAvailability()
	}
	return nil
}

// getLoginActionURL получает URL для авторизации
func (a *Attendance) getLoginActionURL(resp string) (string, error) {
	re := regexp.MustCompile(`"loginAction": "(.*?)"`)
	match := re.FindStringSubmatch(resp)
	if len(match) < 2 {
		return "", customerrors.NewAuthError("site_error", "Ошибка получения ссылки авторизации с сайта MIREA", errors.New("login action not found"))
	}

	return match[1], nil
}

// performLogin выполняет авторизацию с логином и паролем
func (a *Attendance) performLogin(loginActionURL string) (*resty.Response, error) {
	resp, err := a.client.R().
		SetFormData(map[string]string{
			"username":     a.user.Email,
			"password":     a.user.Password,
			"rememberMe":   "on",
			"credentialId": "",
		}).
		SetHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7").
		SetHeader("Origin", "null").
		Post(loginActionURL)
	if err != nil {
		if a.currentProxy != "" {
			_ = proxy.BlockProxy(a.redis, a.currentProxy, 30*time.Second)
		}
		return nil, customerrors.NewAuthError("site_unavailable", "Сайт MIREA недоступен", err)
	}

	return resp, nil
}

// handleTwoFactorAuth обрабатывает двухфакторную авторизацию
func (a *Attendance) handleTwoFactorAuth(loginResp *resty.Response) error {
	if a.user.TotpSecret == "" {
		return customerrors.NewAuthError("totp_secret_required", "Требуется двухфакторная авторизация, но секрет TOTP не установлен", errors.New("totp secret is empty"))
	}

	loginActionURL, err := a.getLoginActionURL(loginResp.String())
	if err != nil {
		return customerrors.NewAuthError("site_error", "Ошибка login_action при двух факторной авторизации", errors.New("login_action not found in two auth page"))
	}

	// Получаем credentialId из ответа (ищем блок с userLabel: "Google Android" и извлекаем id)
	reCredId := regexp.MustCompile(`(?s)"userLabel":\s*"Google Android".*?"id":\s*"(.*?)"`)
	matchCredId := reCredId.FindStringSubmatch(loginResp.String())
	if len(matchCredId) < 2 {
		return customerrors.NewAuthError("site_error", "Ошибка получения credentialId для двухфакторной аутентификации", errors.New("credentialId not found"))
	}

	code, err := totp.GenerateCode(a.user.TotpSecret, time.Now())
	if err != nil {
		return customerrors.NewAuthError("totp_error", "Ошибка генерации TOTP кода", err)
	}

	twoAuthResp, err := a.client.R().
		SetFormData(map[string]string{
			"selectedCredentialId": matchCredId[1],
			"otp":                  code,
			"login":                "Вход",
		}).
		SetHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7").
		SetHeader("Origin", "null").
		Post(loginActionURL)
	if err != nil {
		return customerrors.NewAuthError("site_unavailable", "Сайт MIREA недоступен", err)
	}

	redirects := twoAuthResp.RedirectHistory()
	if len(redirects) == 0 {
		return customerrors.NewAuthError("invalid_credentials", "Неверный логин или пароль от MIREA", errors.New("not redirected after two-factor authorization"))
	}

	if redirects[0].URL != "https://attendance-app.mirea.ru/services" {
		return customerrors.NewAuthError("invalid_credentials", "Неверный логин или пароль от MIREA", errors.New("last redirect is "+redirects[0].URL))
	}

	return nil
}

// makeGRPC универсальный метод для выполнения gRPC-web запросов к attendance-app.mirea.ru
func (a *Attendance) makeGRPC(method string, request proto.Message, response proto.Message) error {
	data, err := proto.Marshal(request)
	if err != nil {
		return errors.New("failed marshal proto")
	}

	padding := []byte{0, 0, 0, 0, byte(len(data))}
	dataWithMeta := append(padding, data...)
	encoded := base64.StdEncoding.EncodeToString(dataWithMeta)

	resp, err := a.client.R().
		SetBody(encoded).
		SetHeader("Accept", "application/grpc-web-text").
		SetHeader("Pulse-app-type", "pulse-app").
		SetHeader("Pulse-app-version", a.appVersion).
		SetHeader("Content-Type", "application/grpc-web-text").
		SetHeader("Origin", "https://attendance-app.mirea.ru").
		SetHeader("Referer", "https://attendance-app.mirea.ru/").
		SetHeader("X-Grpc-Web", "1").
		SetHeader("X-Requested-With", "XMLHttpRequest").
		Post("https://attendance.mirea.ru/" + method)

	if resp.StatusCode() == 401 {
		a.redis.Del(context.Background(), a.getSessionKeyToRedis())
		return errors.New("unauthorized")
	}
	if resp.StatusCode() == 403 {
		if a.currentProxy != "" {
			_ = proxy.BlockProxy(a.redis, a.currentProxy, 30*time.Second)
		}
		return proxyBlockedErr
	}

	if err != nil {
		return err
	}

	if err := decodeProtoResponse(resp.String(), response); err != nil {
		return err
	}

	return nil
}

// GetMeInfo получает информацию о текущем пользователе
func (a *Attendance) GetMeInfo() (*message.Student, error) {
	msg := &message.GetMeInfoRequest{
		Url:   "https://attendance-app.mirea.ru",
		Value: 1,
	}

	response := &message.GetMeInfoResponse{}
	if err := a.makeGRPC("rtu_tc.rtu_attend.app.UserService/GetMeInfo", msg, response); err != nil {
		return nil, err
	}

	student := response.GetBody().GetStudent()

	return student, nil
}

// GetAvailableGroup получает текущую группу пользователя
func (a *Attendance) GetAvailableGroup() (*GroupResponse, error) {
	// я не помню нахуя вообще эта залупа
	if a.user.Group == "" || string([]rune(a.user.Group)[:3]) == "ДПЗ" {
		// Если группа не установлена, берем из списка всех групп
		groups, err := a.GetRelevantAcademicGroupsOfHuman(a.user.ID)
		if err == nil {
			for _, group := range groups {
				info, err := a.GetAcademicGroupInfo(group.GetUuid())
				if err != nil {
					// Какая-то ошибка
					continue
				}

				if info.GetDeparment().GetCode() == "ИДО" || string([]rune(group.GetTitle())[:3]) == "ДПЗ" {
					// Дополнительное образование
					continue
				}

				a.user.Group = group.GetTitle()
				break
			}
		}
	}

	msg := &message.GetMeInfoRequest{
		Url:   "https://attendance-app.mirea.ru",
		Value: 1,
	}

	response := &message.GetAvailableVisitingLogsOfStudentResponse{}
	if err := a.makeGRPC("rtu_tc.attendance.api.VisitingLogService/GetAvailableVisitingLogsOfStudent", msg, response); err != nil {
		return nil, err
	}

	if len(response.GetGroupData()) == 0 {
		return nil, errors.New("empty groups")
	}

	needTerm := response.GetGroupData()[0]

	for _, term := range response.GetGroupData() {
		if term.GetGroup().GetTitle() == a.user.Group && term.GetGroup().GetArchived() == 0 {
			needTerm = term
			break
		}
	}

	return &GroupResponse{
		UUID:  needTerm.GetGroup().GetUuid(),
		Title: needTerm.GetGroup().GetTitle(),
	}, nil
}

// GetLearnRatingScore получает баллы БРС по всем предметам
func (a *Attendance) GetLearnRatingScore() (*message.Response, error) {
	msg := &message.GetLearnRatingScoreRequest{
		Group: a.user.GroupID,
	}

	response := &message.GetLearnRatingScoreResponse{}
	if err := a.makeGRPC("rtu_tc.attendance.api.LearnRatingScoreService/GetLearnRatingScoreReportForStudentInVisitingLogV2", msg, response); err != nil {
		return nil, err
	}

	return response.GetResponse(), nil
}

// SelfApproveAttendance подтверждает присутствие на паре
func (a *Attendance) SelfApproveAttendance(token string) (*message.SelfApproveAttendanceResponse, error) {
	msg := &message.SelfApproveAttendanceRequest{
		Uuid: token,
	}

	response := &message.SelfApproveAttendanceResponse{}
	if err := a.makeGRPC("rtu_tc.attendance.api.StudentService/SelfApproveAttendance", msg, response); err != nil {
		return nil, err
	}

	return response, nil
}

// GetLessons получение расписания по выбранному дню
func (a *Attendance) GetLessons(year, month, day int32) ([]*message.GetAvailableLessonsOfVisitingLogsResponse_Lesson, error) {
	msg := &message.GetAvailableLessonsOfVisitingLogsRequest{
		VisitingLogIds: a.user.GroupID,
		Date: &message.DateInfo{
			Year:  year,
			Month: month,
			Day:   day,
		},
	}

	response := &message.GetAvailableLessonsOfVisitingLogsResponse{}
	if err := a.makeGRPC("rtu_tc.attendance.api.LessonService/GetAvailableLessonsOfVisitingLogs", msg, response); err != nil {
		return nil, err
	}

	return response.GetLessons(), nil
}

// GetAttendanceStudentForLesson скрытый метод для получения списка отмеченных одногруппников
func (a *Attendance) GetAttendanceStudentForLesson(lessonId string) ([]*message.AttendanceStudent, error) {
	msg := &message.GetAttendanceForLessonRequest{
		LessonId: lessonId,
		GroupId:  a.user.GroupID,
	}

	response := &message.GetAttendanceForLessonResponse{}
	if err := a.makeGRPC("rtu_tc.attendance.api.AttendanceService/GetAttendanceForLesson", msg, response); err != nil {
		return nil, err
	}

	return response.GetStudents(), nil
}

// GetHumanAcsEvents получает список всех действий студента в вузе (входы и выходы)
func (a *Attendance) GetHumanAcsEvents(startTime, endTime int64) ([]*message.GetHumanAcsEventsResponse_Info, error) {
	msg := &message.GetHumanAcsEventsRequest{
		StudentId: a.user.ID,
		TimeRange: &message.GetHumanAcsEventsRequest_TimeRange{
			StartTime: &message.GetHumanAcsEventsRequest_Time{Value: startTime},
			EndTime:   &message.GetHumanAcsEventsRequest_TimeTwo{Value: endTime, MegaHuinya: 999000000},
		},
		Huinya1: 1,
		Huinya2: 2,
	}

	response := &message.GetHumanAcsEventsResponse{}
	if err := a.makeGRPC("rtu_tc.rtu_attend.humanpass.HumanPassService/GetHumanAcsEvents", msg, response); err != nil {
		return nil, err
	}

	return response.GetInfo(), nil
}

// GetRelevantAcademicGroupsOfHuman получает доступные группы
func (a *Attendance) GetRelevantAcademicGroupsOfHuman(uuid string) ([]*message.GetRelevantAcademicGroupsOfHumanResponse_Group, error) {
	msg := &message.GetRelevantAcademicGroupsOfHumanRequest{
		Uuid: uuid,
	}

	response := &message.GetRelevantAcademicGroupsOfHumanResponse{}
	if err := a.makeGRPC("rtu_tc.student.api.AcademicGroupService/GetRelevantAcademicGroupsOfHuman", msg, response); err != nil {
		return nil, err
	}

	return response.GetGroups(), nil
}

// GetAcademicGroupInfo получает информацию о группе
func (a *Attendance) GetAcademicGroupInfo(uuid string) (*message.GetAcademicGroupInfoResponse, error) {
	msg := &message.GetAcademicGroupInfoRequest{
		Uuid: uuid,
	}

	response := &message.GetAcademicGroupInfoResponse{}
	if err := a.makeGRPC("rtu_tc.student.api.AcademicGroupService/GetAcademicGroupInfo", msg, response); err != nil {
		return nil, err
	}

	return response, nil
}

// decodeProtoResponse форматирует строку base64 для корректной дешифровки, и дешифрует gRPC
func decodeProtoResponse(respString string, respMessage proto.Message) error {
	respString = strings.TrimSpace(respString)
	respString = strings.ReplaceAll(respString, " ", "")
	respString = strings.ReplaceAll(respString, "\n", "")

	if respString == "" {
		return errors.New("empty response")
	}

	re := regexp.MustCompile(`[A-Za-z0-9+/]+={0,2}`)
	matches := re.FindAllString(respString, -1)
	if len(matches) == 0 {
		return errors.New("wrong base64")
	}
	resp := matches[0]
	resp = strings.TrimSpace(resp)
	resp = strings.ReplaceAll(resp, " ", "")
	resp = strings.ReplaceAll(resp, "\n", "")

	decoded, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		return err
	}

	if len(decoded) < 6 {
		return errors.New("wrong base64")
	}
	length := binary.BigEndian.Uint32(decoded[1:5])
	if uint32(len(decoded)-5) < length {
		return errors.New(fmt.Sprintf("invalid length: expected %d, got %d", length, len(decoded)-5))
	}
	protobufData := decoded[5 : 5+length]

	if err := proto.Unmarshal(protobufData, respMessage); err != nil {
		return errors.New(fmt.Sprintf("proto unmarshal failed: %v", err))
	}

	return nil
}
