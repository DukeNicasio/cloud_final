package services

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtWrapper struct {
	SecretKey       string
	Issuer          string
	ExpirationHours int64
}

type JwtClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func (j *JwtWrapper) GenerateToken(email string) (signedToken string, err error) {
	claims := &JwtClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(j.ExpirationHours) * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err = token.SignedString([]byte(j.SecretKey))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
