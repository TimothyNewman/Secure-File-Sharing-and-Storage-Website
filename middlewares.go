package main

import (
	"net/http"
	"time"
	"context"

	log "github.com/sirupsen/logrus"
)

type key int

const userKey key = 0

func RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		next.ServeHTTP(w, r)
		log.WithFields(log.Fields{
			"path":           r.RequestURI,
			"execution_time": time.Since(startTime).String(),
			"remote_addr":    r.RemoteAddr,
		}).Info("received a new http request")
	})
}

func UserAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie("session_token")
		if err != nil {
			next.ServeHTTP(w, request)
			return
		}
		sessionToken := cookie.Value
		row := db.QueryRow("SELECT username, expires FROM sessions WHERE token = ?", sessionToken)
		var username string
		var expires int64
		err = row.Scan(&username, &expires)
		if err == nil  {
			if time.Now().Before(time.Unix(expires, 0)) {
				request = request.WithContext(context.WithValue(request.Context(), userKey, username))
			}
			next.ServeHTTP(w, request)
		}
	})
}

func getUsernameFromCtx(request *http.Request) string {
	var username string
	usernameCtxValue := request.Context().Value(userKey)
	if usernameCtxValue == nil {
		username = ""
	} else {
		username = usernameCtxValue.(string)
	}
	return username
}

func panicRecovery(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Error(err)
				if rw.Header().Get("Content-Type") == "" {
					rw.WriteHeader(http.StatusInternalServerError)
				}
			}
		}()
		handler.ServeHTTP(rw, rq)
	})
}
