// Main logic/functionality for the web application.
// This is where you need to implement your own server.
package main
// Reminder that you're not allowed to import anything that isn't part of the Go standard library.
// This includes golang.org/x/
import (
	"database/sql"
	"fmt"
	"io/ioutil"
	_ "io/ioutil"
	"net/http"
	"os"
	_ "os"
	"path/filepath"
	_ "path/filepath"
	"strings"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
)

func processRegistration(response http.ResponseWriter, request *http.Request) {
	username := request.FormValue("username")
	password := request.FormValue("password")
	// Check if username already exists
	row := db.QueryRow("SELECT username FROM users WHERE username = ?", username)
	var savedUsername string
	err := row.Scan(&savedUsername)
	if err != sql.ErrNoRows {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(response, "username %s already exists", savedUsername)
		return
	}
	// Generate salt
	const saltSizeBytes = 16
	salt, err := randomByteString(saltSizeBytes)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	hashedPassword := hashPassword(password, salt)
	_, err = db.Exec("INSERT INTO users VALUES (NULL, ?, ?, ?)", username, hashedPassword, salt)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	// Set a new session cookie
	initSession(response, username)
	// Redirect to next page
	http.Redirect(response, request, "/", http.StatusFound)
}

func processLoginAttempt(response http.ResponseWriter, request *http.Request) {
	// Retrieve submitted values
	username := request.FormValue("username")
	password := request.FormValue("password")
	row := db.QueryRow("SELECT password, salt FROM users WHERE username = ?", username)
	// Parse database response: check for no response or get values
	var encodedHash, encodedSalt string
	err := row.Scan(&encodedHash, &encodedSalt)
	if err == sql.ErrNoRows {
		response.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(response, "unknown user")
		return
	} else if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	// Hash submitted password with salt to allow for comparison
	submittedPassword := hashPassword(password, encodedSalt)
	// Verify password
	if submittedPassword != encodedHash {
		fmt.Fprintf(response, "incorrect password")
		return
	}
	// Set a new session cookie
	initSession(response, username)
	// Redirect to next page
	http.Redirect(response, request, "/", http.StatusFound)
}

func processLogout(response http.ResponseWriter, request *http.Request) {
	// get the session token cookie
	cookie, err := request.Cookie("session_token")
	// empty assignment to suppress unused variable warning
	if err!=nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	// get username of currently logged in user
	username := getUsernameFromCtx(request)
	// empty assignment to suppress unused variable warning
	if (username=="") {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	cookie.MaxAge = -1
	http.SetCookie(response, cookie)
	_, err = db.Exec("DELETE FROM sessions WHERE username = ? AND token = ?", username, cookie.Value)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	http.Redirect(response, request, "/", http.StatusSeeOther)
}

func processUpload(response http.ResponseWriter, request *http.Request, username string) {
	file, fileheader, err := request.FormFile("file")
	if err!=nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	count := 0
	fn := fileheader.Filename
	for i:=0; i<len(fn); i++{
		count++
		if (fn[i]>='a'&&fn[i]<='z')||(fn[i]>='A'&&fn[i]<='Z')||(fn[i]>='0'&&fn[i]<='9')||fn[i]=='.'{
			continue
		} else {
			response.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(response, err.Error())
			return
		}
	}
	if count<1 || count>50  {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	bytes, err := ioutil.ReadAll(file)
	if err!=nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	defer file.Close()
	_, err = db.Exec("INSERT INTO files VALUES (NULL, ?, ?, ?)", username, fileheader.Filename, username)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	if !fileExists(filepath.Join("./files", username)) {_=os.Mkdir(filepath.Join("./files", username), 0700)}
	path := filepath.Join("./files", username, fileheader.Filename)
	err = ioutil.WriteFile(path, bytes, 0644)
	if err!=nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
}

// fileInfo helps you pass information to the template
type fileInfo struct {
	Filename  string
	FileOwner string
	FilePath  string
}

func listFiles(response http.ResponseWriter, request *http.Request, username string) {
	files := make([]fileInfo, 0)
	rows, err := db.Query("SELECT owner, filename FROM files WHERE shared = ?", username)
	if err!=nil {
		response.WriteHeader(http.StatusBadRequest)
		log.Info(err)
		fmt.Fprint(response, "User does not have access to this file")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var owner, filename string
		if err := rows.Scan(&owner, &filename); err!=nil {
			response.WriteHeader(http.StatusBadRequest)
			log.Info(err)
			fmt.Fprint(response, "User does not have access to this file")
			return
		}
		path := filepath.Join("./files", owner, filename)
		fInfo := fileInfo{Filename: filename, FileOwner: owner, FilePath: path}
		files = append(files, fInfo)
	}
	data := map[string]interface{}{
		"Username": username,
		"Files":    files,
	}
	tmpl, err := template.ParseFiles("templates/base.html", "templates/list.html")
	if err != nil {
		log.Error(err)
	}
	err = tmpl.Execute(response, data)
	if err != nil {
		log.Error(err)
	}
}

func getFile(response http.ResponseWriter, request *http.Request, username string) {
	fileString := strings.TrimPrefix(request.URL.Path, "/file/")
	dir, filename := filepath.Split(fileString)
	owner := filepath.Base(dir)
	row := db.QueryRow("SELECT shared FROM files WHERE owner = ? AND filename = ? AND shared = ?", owner, filename, username)
	var  hasAccess string
	err := row.Scan(&hasAccess)
	if err!=nil {
		response.WriteHeader(http.StatusBadRequest)
		log.Info(err)
		fmt.Fprint(response, "User does not have access to this file")
		return
	}
	setNameOfServedFile(response, filename)
	http.ServeFile(response, request, fileString)
}

func setNameOfServedFile(response http.ResponseWriter, fileName string) {
	response.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
}

func processShare(response http.ResponseWriter, request *http.Request, sender string) {
	recipient := request.FormValue("username")
	filename := request.FormValue("filename")
	if sender == recipient {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(response, "can't share with yourself")
		return
	}
	userRow := db.QueryRow("SELECT username FROM users WHERE username = ?", recipient)
	var  checkexists string
	err := userRow.Scan(&checkexists)
	if err!=nil {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(response, "user your sharing with does not exist")
		return
	}
	ownerRow := db.QueryRow("SELECT owner FROM files WHERE owner = ? AND filename = ?", sender, filename)
	var  isowner string
	err = ownerRow.Scan(&isowner)
	if err!=nil {
		response.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(response, "You do not have access to share this file.")
		return
	}
	_, err = db.Exec("INSERT INTO files VALUES (NULL, ?, ?, ?)", sender, filename, recipient)
	if err!=nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, "Error when adding user access")
		return
	}
}

// Initiate a new session for the given username
func initSession(response http.ResponseWriter, username string) {
	// Generate session token
	sessionToken, err := randomByteString(16)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	expires := time.Now().Add(sessionDuration)
	// Store session in database
	_, err = db.Exec("INSERT INTO sessions VALUES (NULL, ?, ?, ?)", username, sessionToken, expires.Unix())
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(response, err.Error())
		return
	}
	// Set cookie with session data
	http.SetCookie(response, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expires,
		SameSite: http.SameSiteStrictMode,
	})
}
