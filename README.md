httpserver
====

雑に HTTP サーバーを起動するやつ

## Example

```
package main

import (
	"fmt"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/thamaji/httpserver"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		logger, _ := httpserver.GetLogger(r)
		logger.Println("Hello!!")

		fmt.Fprintln(w, "Hello!!")
	})

	server := httpserver.New(
		mux,
		httpserver.WithPort(8080),
		httpserver.WithGracefulShutdown(30*time.Second, os.Interrupt, syscall.SIGTERM),
		httpserver.WithLogger(httpserver.DefaultLogger),
		httpserver.WithAccessLog(httpserver.DefaultLogFormatter),
		httpserver.WithRecoverer(httpserver.DefaultRecoverer),
	)

	if err := server.ListenAndServe(); err != nil {
		fmt.Println(err)
		return
	}
}
```