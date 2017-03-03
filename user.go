package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"strconv"
)

type UserLogin struct{}

func (l *UserLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if err := CreateNewAuth(w, r); err != nil {
			fmt.Fprintln(w, false)
		} else {
			fmt.Fprintln(w, true)
		}
	}
}

type CheckLogin struct{}

func (c *CheckLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	if r.Method == "GET" || r.Method == "POST" {
		if _, err := isUserCurrentlyLoggedIn(r); err != nil {
			fmt.Fprintln(w, false)
		} else {
			fmt.Fprintln(w, true)
		}
	} else {
		fmt.Fprintln(w, http.StatusNotFound)
	}
}

type UserData struct{}

func (u *UserData) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Pragma", "no-cache")
	if r.Method == "GET" || r.Method == "POST" {
		if ud, err := isUserCurrentlyLoggedIn(r); err != nil {
			fmt.Fprintln(w, false)
		} else {
			uID := ud.ID
			user, err := userProfile(uID)
			if err != nil {
				fmt.Fprintln(w, false)
			}
			if user == nil {
				fmt.Fprintln(w, false)
			}
			json.NewEncoder(w).Encode(user)
		}
	} else {
		fmt.Fprintln(w, http.StatusNotFound)
	}
}

type User struct {
	ID        int    `json:"id"`
	Fullname  string `json:"fullname"`
	Email     string `json:"email"`
	Address   string `json:"address"`
	Telephone string `json:"telephone"`
	Password  string `json:"password"`
	CreatedAt string `json:"registertime"`
}
type CreateUpdateUser struct{}

func (c *CreateUpdateUser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user := &User{}
	if r.Method != "POST" {
		fmt.Fprintln(w, http.StatusForbidden)
		return
	}
	if id := formInt(r, "id"); id != 0 {
		//Existing user
		user.ID = id
	} else {
		//New user
		user.ID = id
	}
	if fn := formString(r, "fullname"); fn != "" {
		user.Fullname = fn
	}
	if eml := formString(r, "email"); eml != "" {
		user.Email = eml
	}
	if adr := formString(r, "address"); adr != "" {
		user.Address = adr
	}
	if tl := formString(r, "telephone"); tl != "" {
		user.Telephone = tl
	}
	if ps := formString(r, "password"); ps != "" {
		user.Password = ps
	}
	var err error
	_, err = json.Marshal(user)
	if err != nil {
		log.Println("Something went wrong!", err)
		fmt.Fprintln(w, false)
	}
	query := ""
	msg := ""
	uAvail, uID, err := checkUserAvail(user.Email)
	if err != nil {
		panic(err)
	}
	if !uAvail && user.ID == 0 {
		saltPass := GenerateHashPassword(user.Password)
		query = "INSERT INTO users(fullname, email, address, telephone, password ) VALUES(?, ?, ?, ?, ?)"
		_, err = Database.Exec(query, user.Fullname, user.Email, user.Address, user.Telephone, saltPass)
		msg = "New user created"
	} else {
		query = "UPDATE users SET fullname=?, email=?, address=?, telephone=? WHERE id=?"
		_, err = Database.Exec(query, user.Fullname, user.Email, user.Address, user.Telephone, uID)
		if user.Password != "" {
			saltPass := GenerateHashPassword(user.Password)
			query = "UPDATE users SET password=? WHERE id=?"
			_, err = Database.Exec(query, saltPass, uID)
		}
		msg = "User updated"
	}
	if err != nil {
		log.Printf("Error: User not saved %v", err)
		fmt.Fprintln(w, false)
	}
	log.Printf("%s", msg)
	fmt.Fprintln(w, true)
}

func checkUserAvail(email string) (bool, int, error) {
	var userID int
	err := Database.QueryRow("SELECT id FROM users WHERE email=?", email).Scan(&userID)
	switch {
	case err == sql.ErrNoRows:
		return false, 0, nil
	case err != nil:
		log.Fatalf("Warning: %v", err)
		return false, 0, err
	default:
		return true, userID, nil
	}
}

func formString(r *http.Request, param string) string {
	pv := r.FormValue(param)
	if pv != "" {
		return pv
	}
	return ""
}

func formInt(r *http.Request, param string) int {
	pv := r.FormValue(param)
	if pv == "" {
		return 0
	}
	iv, err := strconv.Atoi(pv)
	if err != nil {
		panic(err)
	}
	return iv
}

func userProfile(uID int) (*User, error) {
	var userID int
	var fullname string
	var emailAdr string
	var address string
	var telephone string
	var createdAt string
	err := Database.QueryRow("SELECT id, fullname, address, email, telephone, registertime FROM users WHERE id=?", uID).Scan(&userID, &fullname, &address, &emailAdr, &telephone, &createdAt)
	user := &User{
		ID:        userID,
		Fullname:  fullname,
		Email:     emailAdr,
		Address:   address,
		Telephone: telephone,
		CreatedAt: createdAt,
	}
	switch {
	case err == sql.ErrNoRows:
		log.Printf("Warning: %v", err)
		return nil, err
	case err != nil:
		log.Fatal(err)
	default:
		return user, nil
	}
	return user, nil
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" || r.Method == "POST" {
		if _, err := isUserCurrentlyLoggedIn(r); err != nil {
			fmt.Fprint(w, false)
		} else {
			authLogout(w, r)
			fmt.Fprintln(w, true)
		}
	} else {
		fmt.Fprintln(w, http.StatusForbidden)
	}
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" || r.Method == "POST" {
		if err := fetchAndResetPass(r); err != nil {
			fmt.Fprint(w, false)
		} else {
			fmt.Fprintln(w, true)
		}
	} else {
		fmt.Fprintln(w, http.StatusForbidden)
	}
}

func fetchAndResetPass(r *http.Request) error {
	log.Print("sdsd:" + formString(r, "email"))
	if email := formString(r, "email"); email != "" {
		var uID int
		err := Database.QueryRow("SELECT id FROM users WHERE email=?", email).Scan(&uID)
		if err != nil {
			log.Printf("Email not found: %v", err)
			return err
		}
		if uID == 0 {
			return UserEmailNotFound
		}
		if uID != 0 {
			if err := sendResetPass(email); err != nil {
				return err
			} else {
				return nil
			}
		}
	}
	return UserEmailNotFound
}

func sendResetPass(email string) error {
	var uID int
	randPass := fmt.Sprintf("%v", rand.Float64()*5)
	pass := GenerateHashPassword(randPass)
	err := Database.QueryRow("", pass, email).Scan(&uID)
	query := "UPDATE users set password=? WHERE email=?"
	_, err = Database.Exec(query, pass, email)
	if err != nil {
		log.Printf("Not updated: %v", err)
		return err
	}
	auth := smtp.PlainAuth("", "user@test.com", "password", "smtp.gmail.com")
	to := []string{email}
	msg := []byte("To: " + email + "\r\n" +
		"Subject: Reset password!\r\n" +
		"\r\n" +
		"New password: " + randPass + "\r\n" +
		"Thanks \r\n")
	err = smtp.SendMail("smtp.gmail.com:587", auth, "sender@gmail.org", to, msg)
	if err != nil {
		log.Println("Error#", err)
		return err
	}
	fmt.Println("Mail sent!")
	return nil
}
