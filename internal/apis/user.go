package apis

import (
	"context"
	"html"
	"net/http"
	"strconv"

	"dkhalife.com/tasks/core/config"
	authMW "dkhalife.com/tasks/core/internal/middleware/auth"
	"dkhalife.com/tasks/core/internal/models"
	nRepo "dkhalife.com/tasks/core/internal/repos/notifier"
	uRepo "dkhalife.com/tasks/core/internal/repos/user"
	"dkhalife.com/tasks/core/internal/services/logging"
	"dkhalife.com/tasks/core/internal/services/users"
	auth "dkhalife.com/tasks/core/internal/utils/auth"
	"dkhalife.com/tasks/core/internal/utils/email"
	middleware "dkhalife.com/tasks/core/internal/utils/middleware"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	limiter "github.com/ulule/limiter/v3"
	"go.uber.org/zap"
)

type UsersAPIHandler struct {
	userRepo    uRepo.IUserRepo
	userService *users.UserService
	nRepo       *nRepo.NotificationRepository
	email       email.IEmailSender
}

func UsersAPI(ur uRepo.IUserRepo, nRepo *nRepo.NotificationRepository, us *users.UserService, email email.IEmailSender, config *config.Config) *UsersAPIHandler {
	return &UsersAPIHandler{
		userRepo:    ur,
		userService: us,
		nRepo:       nRepo,
		email:       email,
	}
}

func (h *UsersAPIHandler) signUp(c *gin.Context) {
	type SignUpReq struct {
		Email       string `json:"email" binding:"required,email"`
		Password    string `json:"password" binding:"required,min=8,max=45"`
		DisplayName string `json:"displayName" binding:"required"`
	}

	log := logging.FromContext(c)

	var signupReq SignUpReq
	if err := c.BindJSON(&signupReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	password, err := auth.EncodePassword(signupReq.Password)
	signupReq.DisplayName = html.EscapeString(signupReq.DisplayName)

	if err != nil {
		log.Errorf("failed to encode password: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Encoding password failed",
		})
		return
	}

	if err = h.userRepo.CreateUser(c, &models.User{
		Password:    password,
		DisplayName: signupReq.DisplayName,
		Email:       signupReq.Email,
		Disabled:    true,
	}); err != nil {
		log.Errorf("failed to create user: %s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Verify you entered all the fields correctly",
		})
		return
	}

	token, err := auth.GenerateEmailResetToken(c)
	if err != nil {
		log.Errorf("failed to generate token: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to generate activation token",
		})
		return
	}

	err = h.userRepo.SetPasswordResetToken(c, signupReq.Email, token)
	if err != nil {
		log.Errorf("failed to set token: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to set reset token",
		})
		return
	}

	code := auth.EncodeEmailAndCode(signupReq.Email, token)
	go func(name, email, code string, logger *zap.SugaredLogger) {
		ctx := logging.ContextWithLogger(context.Background(), logger)
		h.email.SendWelcomeEmail(ctx, name, email, code)
	}(signupReq.DisplayName, signupReq.Email, code, log)

	c.JSON(http.StatusCreated, gin.H{})
}

func (h *UsersAPIHandler) GetUserProfile(c *gin.Context) {
	currentIdentity := auth.CurrentIdentity(c)
	log := logging.FromContext(c)

	user, err := h.userRepo.GetUser(c, currentIdentity.UserID)
	if err != nil {
		log.Errorf("failed to get user: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get user",
		})
		return
	}

	notificationSettings, err := h.nRepo.GetUserNotificationSettings(c, currentIdentity.UserID)
	if err != nil {
		log.Errorf("failed to get notification settings: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get notification settings",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"display_name":  user.DisplayName,
			"notifications": notificationSettings,
		},
	})
}

func (h *UsersAPIHandler) resetPassword(c *gin.Context) {
	log := logging.FromContext(c)
	type ResetPasswordReq struct {
		Email string `json:"email" binding:"required,email"`
	}

	var req ResetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	_, err := h.userRepo.FindByEmail(c, req.Email)
	if err != nil {
		log.Infof("failed to find user by email: %s", err.Error())
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	token, err := auth.GenerateEmailResetToken(c)
	if err != nil {
		log.Errorf("failed to generate token: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to generate reset token",
		})
		return
	}

	err = h.userRepo.SetPasswordResetToken(c, req.Email, token)
	if err != nil {
		log.Errorf("failed to set token: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to set reset token",
		})
		return
	}

	code := auth.EncodeEmailAndCode(req.Email, token)
	err = h.email.SendResetPasswordEmail(c, req.Email, code)
	if err != nil {
		log.Errorf("failed to send email: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to send email",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *UsersAPIHandler) updateUserPassword(c *gin.Context) {
	log := logging.FromContext(c)

	code := c.Query("c")

	email, code, err := auth.DecodeEmailAndCode(code)
	if err != nil {
		log.Errorf("failed to decode email and code: %s", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid reset code",
		})
		return
	}

	type RequestBody struct {
		Password string `json:"password" binding:"required,min=8,max=32"`
	}

	var body RequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "New password was not provided",
		})
		return

	}

	password, err := auth.EncodePassword(body.Password)
	if err != nil {
		log.Errorf("failed to encode password: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})
		return
	}

	err = h.userRepo.UpdatePasswordByToken(c.Request.Context(), email, code, password)
	if err != nil {
		log.Errorf("failed to update password: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to reset password",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *UsersAPIHandler) CreateAppToken(c *gin.Context) {
	currentIdentity := auth.CurrentIdentity(c)

	var req models.CreateAppTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	status, response := h.userService.CreateAppToken(c, currentIdentity.UserID, req)
	c.JSON(status, response)
}

func (h *UsersAPIHandler) GetAllUserToken(c *gin.Context) {
	currentIdentity := auth.CurrentIdentity(c)
	status, response := h.userService.GetAllAppTokens(c, currentIdentity.UserID)
	c.JSON(status, response)
}

func (h *UsersAPIHandler) DeleteUserToken(c *gin.Context) {
	currentIdentity := auth.CurrentIdentity(c)

	tokenIDRaw := c.Param("id")
	if tokenIDRaw == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Token ID is required",
		})
		return
	}

	tokenID, err := strconv.Atoi(tokenIDRaw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid token ID",
		})
		return
	}

	status, response := h.userService.DeleteAppToken(c, currentIdentity.UserID, tokenID)
	c.JSON(status, response)
}

func (h *UsersAPIHandler) UpdateNotificationSettings(c *gin.Context) {
	currentIdentity := auth.CurrentIdentity(c)

	var req models.NotificationUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	status, response := h.userService.UpdateNotificationSettings(c, currentIdentity.UserID, req)
	c.JSON(status, response)
}

func (h *UsersAPIHandler) updateUserPasswordLoggedInOnly(c *gin.Context) {
	log := logging.FromContext(c)

	currentIdentity := auth.CurrentIdentity(c)

	type RequestBody struct {
		Password string `json:"password" binding:"required,min=8,max=32"`
	}

	var body RequestBody

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	password, err := auth.EncodePassword(body.Password)
	if err != nil {
		log.Errorf("failed to encode password: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to encode password",
		})
		return
	}

	err = h.userRepo.UpdatePasswordByUserId(c.Request.Context(), currentIdentity.UserID, password)
	if err != nil {
		log.Errorf("failed to update password: %s", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to reset password",
		})
		return
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

func UserRoutes(router *gin.Engine, h *UsersAPIHandler, auth *jwt.GinJWTMiddleware, limiter *limiter.Limiter) {
	userRoutes := router.Group("api/v1/users")
	userRoutes.Use(auth.MiddlewareFunc(), middleware.RateLimitMiddleware(limiter))
	{
		userRoutes.GET("/profile", authMW.ScopeMiddleware(models.ApiTokenScopeUserRead), h.GetUserProfile)
		userRoutes.POST("/tokens", authMW.ScopeMiddleware(models.ApiTokenScopeTokenWrite), h.CreateAppToken)
		userRoutes.GET("/tokens", authMW.ScopeMiddleware(models.ApiTokenScopeTokenWrite), h.GetAllUserToken)
		userRoutes.DELETE("/tokens/:id", authMW.ScopeMiddleware(models.ApiTokenScopeTokenWrite), h.DeleteUserToken)
		userRoutes.PUT("/notifications", authMW.ScopeMiddleware(models.ApiTokenScopeUserWrite), h.UpdateNotificationSettings)
		userRoutes.PUT("change_password", authMW.ScopeMiddleware(models.ApiTokenScopeUserWrite), h.updateUserPasswordLoggedInOnly)
	}

	authRoutes := router.Group("api/v1/auth")
	authRoutes.Use(middleware.RateLimitMiddleware(limiter))
	{
		authRoutes.POST("/", h.signUp)
		authRoutes.POST("login", auth.LoginHandler)
		authRoutes.GET("refresh", auth.RefreshHandler)
		authRoutes.POST("reset", h.resetPassword)
		authRoutes.POST("password", h.updateUserPassword)
	}
}
