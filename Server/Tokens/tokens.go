package Tokens

import (
	"github.com/golang-jwt/jwt"
	"os"
	"time"
)

type AccessToken struct {
	Guid  string
	Token string
	jwt.StandardClaims
}

type RefreshToken struct {
	Token string
	jwt.StandardClaims
}

/*
type Tokens struct {
	*AccessToken
	*RefreshToken
}
*/

func GeneratePairTokens() (*AccessToken, *RefreshToken, error) {
	at := &AccessToken{
		Token: "",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
	}

	tokenWithoutKey := jwt.NewWithClaims(jwt.SigningMethodHS512,at.StandardClaims)
	accessToken, err := tokenWithoutKey.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, nil, err
	}
	at.Token = accessToken

	rt := &RefreshToken{
		Token: "",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 3).Unix(),
		},
	}

	tokenWithoutKey = jwt.NewWithClaims(jwt.SigningMethodHS512,rt.StandardClaims)
	refreshToken, err := tokenWithoutKey.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, nil, err
	}
	rt.Token = refreshToken

	return at, rt, nil
}

