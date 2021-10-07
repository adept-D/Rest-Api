package DB

import (
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
	"log"
	server "maked2/Server"
	"os"
	"time"
)

type Config struct {
	client *mongo.Client
}

type DataBase struct {
	RefreshKey string `json:"refresh_key"`
	Expression int64 `json:"expression"`
	GUID string `json:"guid"`
}

func (c *Config) SetConfig(client *mongo.Client) error {
	if client == nil {
		return errors.New("nullptr error ")
	}
	c.client = client
	return nil
}

var config = &Config{}


func (db *DataBase) ConnectToMongo() error {
	url := os.Getenv("MONGODB_URL")

	client, err := mongo.NewClient(options.Client().ApplyURI(url))

	if err != nil{
		return  err
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		return  err
	}
	//defer client.Disconnect(ctx)

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return  err
	}

	err = config.SetConfig(client)
	if err != nil {
		return err
	}

	return  nil

}

func (db *DataBase) InsertInfoToDB(tokens *server.Tokens, GUID string) error {
	err := db.ConnectToMongo()
	if err != nil {
		return err
	}

	hashRefreshKey, err := HashPassword(tokens.RefreshToken.Token)
	if err != nil{
		return  err
	}

	collection := config.client.Database("Refresh_Token").Collection("refresh")

	db.RefreshKey = hashRefreshKey
	//	token, err := refreshToken.CreateToken()
	if err != nil {
		return err
	}
	db.Expression = tokens.RefreshToken.ExpiresAt
	db.GUID = GUID

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	defer config.client.Disconnect(ctx)


	_, err = collection.InsertOne(ctx,db)
	fmt.Println("Insert Values to MongoDB")

	if err != nil{
		log.Fatal("InsertOne error ",err)
	}
	if err != nil {
		return err

	}
	return nil
}



func (db *DataBase) GetHashRefreshKey(tokens *server.Tokens) (isValid  bool,err error) {
	err = db.ConnectToMongo()
	if err != nil{
		return false, err
	}
	collection := config.client.Database("Refresh_Token").Collection("refresh")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	defer config.client.Disconnect(ctx)
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return false, err
	}
	var episodes []bson.M
	if err = cursor.All(ctx, &episodes); err != nil {
		return false, err
	}

	validateInfo := map[string]string{
		"refresh_key": episodes[0]["refreshkey"].(string),
	}
	//fmt.Println(tokens.RefreshToken.Token)
	err = bcrypt.CompareHashAndPassword([]byte(validateInfo["refresh_key"]),[]byte(tokens.RefreshToken.Token))
	if err != nil{
		return false, err
	}

	res, err := collection.DeleteOne(ctx, bson.M{"refreshkey": validateInfo["refresh_key"]})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deleted %v documents\n", res.DeletedCount)

	return true,nil

	//fmt.Println(episodes[0]["guid"])


}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil{
		return "", err
	}
	return string(bytes), err
}


