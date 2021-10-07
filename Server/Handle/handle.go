package Handle

import "net/http"
import handlers "maked2/Server/Handlers"

func StartServer() error {
	http.HandleFunc("/login",handlers.HelloHandler )
	http.HandleFunc("/", handlers.IsAuth(handlers.Login))
	http.HandleFunc("/refresh",handlers.Refresh)
	//	http.HandleFunc("/login/auth", nil)

	err := http.ListenAndServe(":3000", nil)

	if err != nil {
		return err
	}

	return nil
}
