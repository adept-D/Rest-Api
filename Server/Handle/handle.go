package Handle

import "net/http"
import handlers "maked2/Server/Handlers"

func StartServer() error {
	http.HandleFunc("/", handlers.HomePage)
	http.HandleFunc("/login", handlers.IsAuth(handlers.Login))
	http.HandleFunc("/refresh", handlers.Refresh)

	err := http.ListenAndServe(":3000", nil)

	if err != nil {
		return err
	}

	return nil
}
