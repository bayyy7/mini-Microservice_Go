package handler

import (
	"mini-microservice_go/auth/model"
	"mini-microservice_go/auth/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthInterface interface {
	AuthLogin(*gin.Context)
	AuthSignUp(*gin.Context)
}

type authImplement struct {
	db     *gorm.DB
	jwtKey []byte
}

func NewAuth(db *gorm.DB, jwtKey []byte) AuthInterface {
	return &authImplement{
		db,
		jwtKey,
	}
}

type authPayload struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
}

func (a *authImplement) AuthLogin(ctx *gin.Context) {
	payload := authPayload{}

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	auth := model.Auth{}
	if err := a.db.Where("username = ?", payload.Username).First(&auth).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Username not found",
			})
			return
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(auth.Password), []byte(payload.Password)); err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": "Wrong password",
		})
		return
	}

	token, err := a.GenerateJWT(&auth)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "success",
		"token":   token,
	})
}

func (a *authImplement) AuthSignUp(ctx *gin.Context) {
	payload := authPayload{}

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if !utils.CharacterCheck(payload.Username) && !utils.CharacterCheck(payload.Password) {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"message": "Username or Password must be Alphanumeric",
		})
		return
	}

	tx := a.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	existingUser := model.Auth{}
	if result := tx.Where("username = ?", payload.Username).First(&existingUser); result.RowsAffected > 0 {
		tx.Rollback()
		ctx.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "username already exist",
		})
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	newUser := model.Auth{
		Username: payload.Username,
		Password: string(hashPassword),
	}

	newAccount := model.Account{
		Name:    payload.Name,
		Balance: 0,
	}

	if err := tx.Create(&newUser).Error; err != nil {
		tx.Rollback()
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	newAccount.AccountID = newUser.AccountID
	if err := tx.Create(&newAccount).Error; err != nil {
		tx.Rollback()
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message":  "User register successfully",
		"username": payload.Username,
	})
}
