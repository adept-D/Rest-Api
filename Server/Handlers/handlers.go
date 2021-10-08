package Handlers

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"log"
	"maked2/DB"
	"maked2/Server/Tokens"
	"net/http"
	"os"
	"strings"
	"time"
)

var tokensInfo = &Tokens.Tokens{}

func InitTokens() error {
	var err error
	tokensInfo, err = tokensInfo.InitTokens()
	if err != nil {
		return err
	}
	return nil
}

func SecretPage(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("Вы подключились на защищенную страницу"))
	if err != nil {
		return
	}
}

var Login = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	var GUID = strings.Join(query["guid"], "")

	if GUID == "" {
		InfoPage(rw, r)
		return
	}
	SendTokens(rw, r)

})

func HomePage(rw http.ResponseWriter, _ *http.Request) {
	rw.Write([]byte("Зарегистрируйте по адресу http://localhost:3000/login с помощью GET запроса"))
}

func InfoPage(rw http.ResponseWriter, _ *http.Request) {
	_, err := rw.Write([]byte("Вы не авторизованы отправьте GUID запрос в параметре"))
	if err != nil {
		return
	}
}

var db = DB.DataBase{}

func SendTokens(rw http.ResponseWriter, r *http.Request) {
	err := InitTokens()
	if err != nil {
		rw.Write([]byte("Произошла ошибка"))
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     "Token",
		Value:    tokensInfo.AccessToken.Token,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(tokensInfo.AccessToken.ExpiresAt, 0),
	})

	if err := db.InsertInfoToDB(tokensInfo); err != nil {
		log.Fatal("Insert info to DB error ", err)
	}
	SecretPage(rw, r)

}

func IsAuth(endPoint func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("Token")

		if c != nil && tokensInfo.AccessToken != nil {
			token, err := jwt.ParseWithClaims(
				c.Value,&tokensInfo.AccessToken.StandardClaims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, errors.New("SigningMethodHMAC error")
					}
					return []byte(os.Getenv("ACCESS_SECRET")), nil

				})

			if err != nil {
				_, err := rw.Write([]byte("Неправильный токен "))
				if err != nil {
					log.Fatal(err)
				}
				return
			}
			if token.Valid {
				SecretPage(rw, r)
			}
		} else if tokensInfo.AccessToken != nil && tokensInfo.RefreshToken != nil {
			if time.Unix(tokensInfo.AccessToken.ExpiresAt, 0).Sub(time.Now()) < 30*time.Second ||
				time.Unix(tokensInfo.RefreshToken.ExpiresAt, 0).Sub(time.Now()) < 30*time.Second {
				_, err := rw.Write([]byte(
					"Ваш токен истек получите новую пару Access/Refresh по адресу http://localhost:3000/refresh "))
				if err != nil {
					log.Fatal(err)
				}
			} else {
				SecretPage(rw, r)
			}
		} else {
			endPoint(rw, r)
		}

	}
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	if tokensInfo.AccessToken != nil && tokensInfo.RefreshToken != nil {
		isValid, err := db.GetHashRefreshKey(tokensInfo)
		if err != nil {
			log.Fatal(err)
		}

		if isValid {
			//ts := &server.Tokens{}
			fmt.Println("Before: ", tokensInfo.RefreshToken.Token)
			err := InitTokens()
			if err != nil {
				w.Write([]byte("Произошла ошибка"))
				return
			}

			err = db.InsertInfoToDB(tokensInfo)
			if err != nil {
				return
			}

			w.Write([]byte("Новые Access/Refresh токены получены"))
			// Set the new token as the users `token` cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "Token",
				Value:    tokensInfo.AccessToken.Token,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Expires:  time.Unix(tokensInfo.AccessToken.ExpiresAt, 0),
			})
		} else {
			w.Write([]byte("Ваш рефреш токен не соответствует требованиям"))
		}
	} else {
		InfoPage(w, r)
	}

}
