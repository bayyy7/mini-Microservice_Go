package handler

import (
	"fmt"
	"net/http"

	"auth"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type AuthInterface interface {
	AuthLogin(*gin.Context)
	AuthSignup(*gin.Context)
}

type authImplement struct {
	db         *gorm.DB
	authClient auth.authClient
}

func NewAuth(db *gorm.DB, authClient auth.authClient) AuthInterface {
	return &authImplement{
		db,
		authClient,
	}
}

type authLoginPayload struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (a *authImplement) AuthLogin(ctx *gin.Context) {
	payload := authLoginPayload{}

	err := ctx.ShouldBindJSON(&payload)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	req := &auth.AuthLoginRequest{
		Username: payload.Username,
		Password: payload.Password,
	}

	res, err := a.authClient.Login(ctx, req)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Unauthenticated:
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": e.Message()})
			case codes.Internal:
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": e.Message()})
			default:
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": e.Message()})
			}
		}
		return
	}

	// response to client
	ctx.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("%v Login Sukses", payload.Username),
		"data":    res.Token,
	})
}

type authSignupPayload struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
}

func (a *authImplement) AuthSignup(ctx *gin.Context) {
	payload := authSignupPayload{}

	err := ctx.ShouldBindJSON(&payload)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

}
