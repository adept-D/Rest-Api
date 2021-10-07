package Handlers

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"log"
	"maked2/DB"
	server "maked2/Server"
	"net/http"
	"os"
	"strings"
	"time"
)

var tokens = &server.Tokens{}

func InitTokens(){
	var err error
	tokens, err = tokens.InitTokens()
	if err != nil{
		log.Fatal("AAAAAAAAAAA")
	}
	fmt.Println("Init Tokens...")
}



func SecretPage(w http.ResponseWriter, r *http.Request){
	_, err := w.Write([]byte("You get success connected to secret page"))
	if err != nil {
		return 
	}
}

var TempHandler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	_, err := rw.Write([]byte("You are not auth"))
	if err != nil {
		return 
	}
})


var users = make([]string,10)

var Login = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	var GUID = strings.Join(query["guid"], "")

	if GUID == "" {
		HelloHandler(rw,r)
		return
	}
	SendTokens(rw,r, GUID)
	//tokens.AccessToken.Guid = GUID

	/*
	users = append(users,GUID)

	for _, el := range users{
		if GUID == el {
			SecretPage(rw,r)
		}
	}


	 */

})

func HelloHandler (rw http.ResponseWriter, _ *http.Request) {
	_, err := rw.Write([]byte("You are not auth, Get GUID in Request "))
	if err != nil {
		return
	}
}
var db = DB.DataBase{}
func SendTokens(rw http.ResponseWriter, r *http.Request, guid string) {
	InitTokens()
	tokens.AccessToken.Guid = guid
	http.SetCookie(rw,&http.Cookie{
		Name: "Token",
		Value:      tokens.AccessToken.Token,
		Secure:     true,
		HttpOnly:   true,
		SameSite: http.SameSiteStrictMode,
		Expires: time.Unix(tokens.AccessToken.ExpiresAt,0),

	})

	/*if err := db.ConnectToMongo(); err != nil {
		log.Fatal("ConnectToMongo to MongoDb error: ",err)
	}*/
	if err := db.InsertInfoToDB(tokens, guid); err != nil {
		log.Fatal("Insert info to DB error ",err)
	}
	SecretPage(rw,r)

}

func IsAuth(endPoint func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
//	var isTokenExp = false
	return func(rw http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("Token")

		if c != nil {
			token, err := jwt.Parse(
				c.Value, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, errors.New("SigningMethodHMAC error")
					}
					return []byte(os.Getenv("ACCESS_SECRET")), nil

				})


			if err != nil {

				rw.Write([]byte("Неправильный токен "))
				//endPoint(rw, r)
				return
			}
			if time.Unix(tokens.AccessToken.ExpiresAt, 0).Sub(time.Now()) < 30*time.Second{
				rw.Write([]byte("Ваш токен истек получите новую пару Access/Refresh по адрус /refresh "))
				return
			}
			if token.Valid {
				SecretPage(rw,r)
			}
		} else {
			//	_, err := rw.Write([]byte("Not auth"))
			endPoint(rw, r)
			//	if err != nil {
			//		log.Fatal("Write error: ", err)
			//	}
		}
	}
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("Token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := c.Value

	tkn, err := jwt.ParseWithClaims(
		tknStr,&tokens.AccessToken.StandardClaims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("SigningMethodHMAC error")
			}
			return []byte(os.Getenv("ACCESS_SECRET")), nil

		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	isValid, err := db.GetHashRefreshKey(tokens)
	if err != nil {
		log.Fatal(err)
	}

	if isValid {
		//ts := &server.Tokens{}
		fmt.Println("Before: ",tokens.RefreshToken.Token)
		InitTokens()


		err = db.InsertInfoToDB(tokens, "")
		if err != nil {
			return
		}

		// Set the new token as the users `token` cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "Token",
			Value:   tokens.AccessToken.Token,
			Expires: time.Unix(tokens.AccessToken.ExpiresAt, 0),
		})
	}else{
		w.Write([]byte("Ваш рефреш токен не соответствует требуемому"))
	}
}

