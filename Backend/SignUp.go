package forum

import (
	_ "github.com/mattn/go-sqlite3"
	"html/template"
	"net/http"
	"strings"
	"fmt"
	"log"
)

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	var tmpl = template.Must(template.ParseFiles("./Pages/SignUp.html"))
	if r.Method == "GET" {
		// Display the account creation form
		err := tmpl.Execute(w, map[string]interface{}{
			"Error": "",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		var account Account
		account.Email = r.FormValue("email")
		account.Username = r.FormValue("username")
		account.Password = r.FormValue("password")
		ConfirmPassword := r.FormValue("ConfirmPassword")
		action := r.FormValue("action")

		exists, err := AccountExists(account.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		switch action {
		case "login":
			http.Redirect(w, r, "/", http.StatusFound)
		case "signup":
			if account.Email == "" || account.Username == "" || account.Password == "" {
				errorMessage := "Please Fill All The Boxes"
				Template(w, tmpl, errorMessage)
			} else if !isValidEmail(account.Email) {
				errorMessage := "Invalid Email Format"
				Template(w, tmpl, errorMessage)
			} else if !isValidString(account.Email) || !isValidString(account.Username) || !isValidString(account.Password) {
				errorMessage := "Unallowed Charachters"
				Template(w, tmpl, errorMessage)
			} else if exists {
				errorMessage := "Email already exists! Go to the Login page"
				Template(w, tmpl, errorMessage)
				http.Redirect(w, r, "/", http.StatusFound)
			} else if ConfirmPassword != account.Password {
				errorMessage := "Password confirmation does not match the account password."
				Template(w, tmpl, errorMessage)
			} else {
				password := encrytion(account.Password)
				ID, errorMessage, err := AddAccount(account.Email, account.Username, password, "N")
				if errorMessage != "" {
					Template(w, tmpl, errorMessage)
				}

				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				sessionID, expt := Cookies(w)
				SessionID(ID, sessionID, expt)
				guest = false
				http.Redirect(w, r, "/HomePage", http.StatusFound)
			}
		case "guest":
			guest = true
			http.Redirect(w, r, "/HomePage", http.StatusFound)
		}
	}
}


func GLogin (w http.ResponseWriter, r *http.Request ,Uname string, UEmail string) {
	// check if account Exists
	var ID int64
	exists, err := AccountExists(UEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	 if !exists {
		//http.Redirect(w, r, "/", http.StatusFound)
		ID, _, err = AddAccount(UEmail, Uname, "", "G")
	
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sessionID, expt := Cookies(w)
				SessionID(ID, sessionID, expt)
				guest = false
				http.Redirect(w, r, "/HomePage", http.StatusFound)
	} else if AccountG(UEmail) {

		ID, err = GetAccountID(UEmail, Uname)
		if err !=nil {
			fmt.Print("help")
		}
		sessionID, expt := Cookies(w)
				SessionID(ID, sessionID, expt)
				guest = false
				http.Redirect(w, r, "/HomePage", http.StatusFound)
	} else {
		errorMessage = "Account Already exists"
		http.Redirect(w, r, "/", http.StatusFound)
		
	
	}
				
}

func AccountG(Email string) bool {
	var kind string
	err = Accountsdb.QueryRow("SELECT Type FROM accounts WHERE Email = ?", Email).
		Scan(&kind)
	if err != nil {
		log.Fatal(err)
	}
	if kind == "G" {
		return true
	}
	return false

}


	

func AddAccount(email, username, password string, kind string) (int64, string, error){
	errorMessage := ""
	insertQuery := "INSERT INTO accounts (Email, Username, Password, Type) VALUES (?, ?, ?, ?)"
	
	result, err := Accountsdb.Exec(insertQuery, email, username, password, kind)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: accounts.Username") {
			errorMessage = "Username is already taken. Please choose a different username."
			fmt.Println(errorMessage)
			return 0 , errorMessage, nil
		} else {
			errorMessage = "An error occurred while creating the account. Please try again later."
			return 0 , errorMessage , nil
		}
	}

	Id, err := result.LastInsertId()
	if err != nil {
		return 0, errorMessage, err
	}
	return Id , errorMessage, nil
}
