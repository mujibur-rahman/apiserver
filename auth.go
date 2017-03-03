//auth.go
//Its belonging all auth implementation
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/securecookie"
	"log"
	"net/http"
	"time"
)

var (
	hashKey            = securecookie.GenerateRandomKey(64)
	blockKey           = securecookie.GenerateRandomKey(32)
	sc                 = securecookie.New(hashKey, blockKey)
	NotFoundCookie     = errors.New("Cookie not found")
	FieldRequiredEmpty = errors.New("Required field empty")
	UserNotFound       = errors.New("user not found")
	UserEmailNotFound  = errors.New("email not found")
)

//Auth represents the middleware wrapper to keep auth functions
type Auth struct{}

func NewAuth() *Auth {
	return &Auth{}
}

func CreateNewAuth(w http.ResponseWriter, r *http.Request) error {
	email := r.FormValue("email")
	password := r.FormValue("password")
	if email == "" {
		return FieldRequiredEmpty
	}
	if password == "" {
		return FieldRequiredEmpty
	}
	user := getUser(email, password)
	if user != nil && user.ID != 0 {
		if err := createCookie(user, w); err != nil {
			return err
		} else {
			return nil
		}
	}
	return UserNotFound
}

func createCookie(user *User, w http.ResponseWriter) error {
	value := map[string]interface{}{
		"cookie-set-date": time.Now().Unix(),
	}
	encoded, err := sc.Encode("USSID", value)
	if err != nil {
		return err
	}
	MemoryCookie[encoded] = user
	cookie := fmt.Sprintf("USSID=%s; Path=/", encoded)
	w.Header().Add("Set-Cookie", cookie)
	return nil
}

func authLogout(w http.ResponseWriter, r *http.Request) {
	cs, err := r.Cookie("USSID")
	if err != nil {
		log.Println("Warning cookie empty: ", err)
	}
	if cs != nil && cs.Value != "" {
		if _, ok := MemoryCookie[cs.Value]; ok {
			delete(MemoryCookie, cs.Value)
			log.Println("Auth logout")
		}
	}
}

func isUserCurrentlyLoggedIn(r *http.Request) (*User, error) {
	cs, err := r.Cookie("USSID")
	if err != nil {
		log.Println("Warning cookie empty: ", err)
		return nil, err
	}
	if cs != nil && cs.Value != "" {
		if ud, ok := MemoryCookie[cs.Value]; ok {
			//Cookie valid because user has already loggedin to the system
			return ud, nil
		}
	}
	return nil, NotFoundCookie
}

func getUser(email, password string) *User {
	var uID int
	var fullname string
	var emailAdr string
	var address string
	var telephone string

	saltPass := GenerateHashPassword(password)
	err := Database.QueryRow("SELECT id, fullname, address, email, telephone FROM users WHERE email=? AND password=?", email, saltPass).Scan(&uID, &fullname, &address, &emailAdr, &telephone)
	user := &User{
		ID:        uID,
		Fullname:  fullname,
		Email:     emailAdr,
		Address:   address,
		Telephone: telephone,
	}
	switch {
	case err == sql.ErrNoRows:
		log.Printf("Warning: %v", err)
		return user
	case err != nil:
		log.Fatal(err)
	default:
		return user
	}
	return user
}

func GenerateHashPassword(password string) string {
	var hash string
	sha := sha256.New()
	sha.Write([]byte(password))
	hash = base64.URLEncoding.EncodeToString(sha.Sum(nil))
	return hash
}
