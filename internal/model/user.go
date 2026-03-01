package model

type UserResponse struct {
	ID            string `json:"id,omitempty"`
	TelegramID    int64  `json:"telegram_id"`
	Email         string `json:"email"`
	Fullname      string `json:"fullname,omitempty"`
	Group         string `json:"group,omitempty"`
	CustomProxy   string `json:"custom_proxy,omitempty"`
	HasTotpSecret bool   `json:"has_totp_secret,omitempty"`
	CreatedAt     int64  `json:"created_at,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`
}

type AnotherStudentResponse struct {
	Email    string `json:"email"`
	Fullname string `json:"fullname,omitempty"`
	Group    string `json:"group,omitempty"`
}

type ConnectedStudentResponse struct {
	Email    string `json:"email"`
	Fullname string `json:"fullname"`
	Group    string `json:"group"`
	Enabled  bool   `json:"enabled"`
}

type RegisterUserRequest struct {
	TelegramId   int64  `json:"-"`
	TelegramHash string `json:"-"` // из middleware (webAppUser.hash)
	Email        string `json:"email" validate:"required,email,mireaDomain"`
	Password     string `json:"password" validate:"required,max=100"`
}

// OtpRequiredResponse — ответ sign-up при необходимости ввода OTP
type OtpRequiredResponse struct {
	OtpRequired  bool   `json:"otp_required"`
	TelegramHash string `json:"telegram_hash"`
	OtpType      string `json:"otp_type"` // "email" | "max"
}

type SubmitOtpRequest struct {
	OtpCode      string `json:"otp_code" validate:"required,len=6"`
	TelegramHash string `json:"telegram_hash" validate:"required"`
}

// OtpPendingData — данные в Redis при ожидании OTP (ключ: otp_pending:<telegram_hash>)
type OtpPendingData struct {
	TelegramId     int64  `json:"telegram_id"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	LoginActionURL string `json:"login_action_url"`
	OtpType        string `json:"otp_type"` // "email" | "max"
}

type LoginUserRequest struct {
	Username string `json:"username" validate:"required,max=100"`
	Password string `json:"password" validate:"required,max=100"`
}

type ConnectStudentRequest struct {
	TelegramId int64  `json:"-"`
	Email      string `json:"email" validate:"required,email,mireaDomain"`
}

type ChangePasswordRequest struct {
	TelegramId  int64  `json:"-"`
	NewPassword string `json:"new_password" validate:"required,max=100"`
}

type UpdateProxyRequest struct {
	TelegramId int64  `json:"-"`
	Proxy      string `json:"proxy" validate:"omitempty,max=500"`
}

type UpdateTotpSecretRequest struct {
	TelegramId int64  `json:"-"`
	TotpSecret string `json:"totp_secret" validate:"required,max=100"`
}

type UniversityStatusResponse struct {
	IsInUniversity bool                    `json:"is_in_university"`
	EntryTime      int64                   `json:"entry_time,omitempty"`
	ExitTime       int64                   `json:"exit_time,omitempty"`
	Events         []UniversityEventDetail `json:"events,omitempty"`
}

type UniversityEventDetail struct {
	Time          int64  `json:"time"`
	EntryLocation string `json:"entry_location"`
	ExitLocation  string `json:"exit_location"`
	IsEntry       bool   `json:"is_entry"`
}
