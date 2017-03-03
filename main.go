package main

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"net/http"
	"os"
	"runtime/debug"
)

var (
	port      *int
	debugPort *int
	logToFile *bool
	logFile   = "log/web-access.log"
	//MemoryCookie saved in memory, we can save in either memcache/redis later
	MemoryCookie = make(map[string]*User)
)

func init() {
	port = flag.Int("port", 6000, "Http running on port")
	debugPort = flag.Int("debugPort", 6060, "Port to listen for debugging")
	logToFile = flag.Bool("logToFile", true, "Log to file?")
}

func setupLogging() {
	logWriteTo, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Error opening to log file: %v", err)
	}
	if logWriteTo != nil {
		log.SetOutput(logWriteTo)
	}

}

func panicRecover() {
	defer func() {
		if res := recover(); res != nil {
			log.Println(res)
			log.Printf("%s\n", debug.Stack())
		}
	}()
}

//Database represents a global variable which will be used in whole applications
var Database *sql.DB

func main() {
	panicRecover()
	log.SetFlags(log.Lshortfile | log.Ldate | log.Lmicroseconds)
	flag.Parse()
	if *logToFile {
		//Decide what we want to write log to file or stdout?
		setupLogging()
	}
	if *debugPort > 0 {
		go func() {
			log.Println(http.ListenAndServe(fmt.Sprintf("localhost:%d", *debugPort), nil))
		}()
	}

	db, err := sql.Open("mysql", "root:root@/social")
	if err != nil {
		panic(err)
	}
	Database = db
	defer db.Close()
	//web server health check
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong\n")
	})
	http.Handle("/login", &UserLogin{})
	http.Handle("/checkLogin", &CheckLogin{})
	http.Handle("/register", &CreateUpdateUser{})
	http.Handle("/user", &UserData{})
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/resetPass", resetPassword)
	listenAddr := fmt.Sprintf(":%d", *port)
	log.Printf("PID: %d web server listening at port %s", os.Getpid(), listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
