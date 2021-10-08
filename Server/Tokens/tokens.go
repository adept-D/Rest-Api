package Tokens

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"log"
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

type Tokens struct {
	AccessToken  *AccessToken
	RefreshToken *RefreshToken
}

func GeneratePairTokens() (*AccessToken, *RefreshToken, error) {
	at := &AccessToken{
		Token: "",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
	}

	tokenWithoutKey := jwt.NewWithClaims(jwt.SigningMethodHS512, at.StandardClaims)
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

	tokenWithoutKey = jwt.NewWithClaims(jwt.SigningMethodHS512, rt.StandardClaims)
	refreshToken, err := tokenWithoutKey.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, nil, err
	}
	rt.Token = refreshToken

	return at, rt, nil
}

func (t *Tokens) InitTokens() (*Tokens, error) { //constructor
	log.Println("Tokens initialized...")
	at, rt, err := GeneratePairTokens()
	if err != nil {
		return nil, err
	}
	return &Tokens{
		AccessToken:  at,
		RefreshToken: rt,
	}, nil
}

func (t *Tokens) GetTokens() (*Tokens, error) {
	if t.AccessToken == nil || t.RefreshToken == nil {
		return nil, errors.New("nullptr objects error")
	}

	return &Tokens{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
	}, nil
}
