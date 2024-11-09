package handler

import (
	"auth/model"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (a *authImplement) GenerateJWT(auth *model.Auth) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["auth_id"] = auth.AuthID
	claims["account_id"] = auth.AccountID
	claims["username"] = auth.Username
	claims["exp"] = time.Now().Add(time.Hour * 2).Unix()

	tokenString, err := token.SignedString(a.jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
