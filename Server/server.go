package Server

import (
	"errors"
	"log"
	tokens "maked2/Server/Tokens"
)

type Tokens struct {
	AccessToken  *tokens.AccessToken
	RefreshToken *tokens.RefreshToken
}

func (t *Tokens) InitTokens()(*Tokens, error){ //constructor
	log.Println("Tokens initialized...")
	at,rt, err:= tokens.GeneratePairTokens()
	if err != nil{
		return  nil,err
	}
	return  &Tokens{
		AccessToken: at,
		RefreshToken: rt,
	},nil
}

/*
func (t *Tokens) SetTokens(at *tokens.AccessToken,rt *tokens.RefreshToken) error  {
	//at, rt, err := t.InitTokens()
	if at == nil || rt == nil{
		return  errors.New("nullptr objects error")
	}

	t.AccessToken = at
	t.RefreshToken = rt

	return nil
}

 */

func (t *Tokens) GetTokens() (*Tokens, error){
	if t.AccessToken == nil || t.RefreshToken == nil{
		return nil, errors.New("nullptr objects error")
	}

	return &Tokens{
		AccessToken: t.AccessToken,
		RefreshToken: t.RefreshToken,
	}, nil
}

/*
var token  = &Tokens{}


func Init() {
	err := token.SetTokens()
	if err != nil {
		log.Fatal(err)
	}

}

func  GetTokens() *Tokens {
	return &Tokens{
		AccessToken: token.AccessToken,
		RefreshToken: token.RefreshToken,
	}
}



 */