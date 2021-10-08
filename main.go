package main

import (
	"github.com/joho/godotenv"
	"log"
	handle "maked2/Server/Handle"
)

func main() {
	if err := godotenv.Load("./values.env"); err != nil {
		log.Fatal(err)
	}

	if err := handle.StartServer(); err != nil {
		log.Fatal(err)
	}
}
