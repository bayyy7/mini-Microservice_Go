package handler

import (
	"auth/model"
	pb "auth/proto"
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type authImplement struct {
	pb.UnimplementedAuthServer
	db         *gorm.DB
	signingKey []byte
}

func NewAuth(db *gorm.DB, signingKey []byte) pb.AuthServer {
	return &authImplement{
		db:         db,
		signingKey: signingKey,
	}
}

func (a *authImplement) Login(ctx context.Context, req *pb.AuthLoginRequest) (*pb.AuthLoginResponse, error) {
	auth := model.Auth{}
	if err := a.db.Where("username = ?", req.Username).
		First(&auth).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, status.Error(codes.Unauthenticated, "Login not valid")
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword([]byte(auth.Password), []byte(req.Password)); err != nil {
		return nil, status.Error(codes.Unauthenticated, "Login not valid")
	}

	// Login valid, create token
	token, err := a.GenerateJWT(&auth)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Success Response
	return &pb.AuthLoginResponse{
		Token: token,
	}, nil
}

func (a *authImplement) Validate(ctx context.Context, req *pb.AuthValidateRequest) (*pb.AuthValidateResponse, error) {
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrAbortHandler
		}
		return []byte(a.signingKey), nil
	})
	if err != nil || !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "Unauthenticated")
	}

	response := &pb.AuthValidateResponse{}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if authID, ok := claims["auth_id"].(float64); ok {
			response.AuthId = int64(authID)
		}
		if accountID, ok := claims["account_id"].(float64); ok {
			response.AccountId = int64(accountID)
		}
		if username, ok := claims["username"].(string); ok {
			response.Username = username
		}
	} else {
		return nil, status.Error(codes.Unauthenticated, "Unauthenticated")
	}

	return response, nil
}

func (a *authImplement) Signup(ctx context.Context, req *pb.AuthSignupRequest) (*pb.AuthSignupResponse, error) {
	tx := a.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	existingUser := model.Auth{}
	if result := tx.Where("username = ?", req.Username).First(&existingUser); result.RowsAffected > 0 {
		tx.Rollback()
		return nil, status.Error(codes.AlreadyExists, "Username already exist")
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	model := model.Auth{
		Username: req.Username,
		Password: string(hashPassword),
	}

	if err := tx.Create(&model).Error; err != nil {
		tx.Rollback()
		return nil, status.Error(codes.Unknown, err.Error())
	}

	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return nil, status.Error(codes.Unknown, err.Error())
	}

	return &pb.AuthSignupResponse{
		AccountId: int64(model.AccountID),
	}, nil
}
