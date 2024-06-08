package main

import (
	"encoding/json"
	"fmt"
	forum "forum/Backend"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	_ "github.com/mattn/go-sqlite3"
)

const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	githubAuthURL     = "https://github.com/login/oauth/authorize"
	githubTokenURL    = "https://github.com/login/oauth/access_token"
	githubUserInfoURL = "https://api.github.com/user"
)

type Config struct {
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"google_client_secret"`
	GoogleRedirectURI  string `json:"google_redirect_uri"`
	GithubClientID     string `json:"github_client_id"`
	GithubClientSecret string `json:"github_client_secret"`
	GithubRedirectURI  string  `json:"GithubRedirectURI"`
}

type UserProfile struct {
    ID            string `json:"id"`
    Email         string `json:"email"`
    VerifiedEmail bool   `json:"verified_email"`
    Picture       string `json:"picture"`
    Name         string `json:"name"`
}

type UserResponse struct {
    Name        string `json:"name"`
    Email       string `json:"email,omitempty"`
    AvatarURL   string `json:"avatar_url"`
}

var wayy bool

func loadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func googleLoginHandler(config *Config) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {

        authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
            googleAuthURL, config.GoogleClientID, config.GoogleRedirectURI)
        http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
    }
}

func googleCallbackHandler(config *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("second")
		code := r.URL.Query().Get("code")
		tokenURL := fmt.Sprintf("%s?client_id=%s&client_secret=%s&code=%s&grant_type=authorization_code&redirect_uri=%s",
			googleTokenURL, config.GoogleClientID, config.GoogleClientSecret, code, config.GoogleRedirectURI)

		resp, err := http.PostForm(tokenURL, url.Values{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var tokenResponse map[string]interface{}
		if err := json.Unmarshal(respBody, &tokenResponse); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		accessToken := tokenResponse["access_token"].(string)
		userInfoReq, err := http.NewRequest("GET", googleUserInfoURL, nil)
		userInfoReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		userInfoResp, err := http.DefaultClient.Do(userInfoReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer userInfoResp.Body.Close()

		userInfoBody, err := ioutil.ReadAll(userInfoResp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//fmt.Fprintf(w, "Welcome, %s!", userInfoBody)
		var userProfile UserProfile
        err = json.Unmarshal(userInfoBody, &userProfile)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }


	Uname:= userProfile.Name
	UEmail := userProfile.Email
	Uprofile := userProfile.Picture

	forum.GLogin(w,r,Uname, UEmail, Uprofile)


 }
}


func githubLoginHandler(config *Config) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {

        authURL := fmt.Sprintf(
            "https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=user:email",
            config.GithubClientID, config.GithubRedirectURI,
        )
        http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
    }
}

func githubCallbackHandler(config *Config) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        code := r.URL.Query().Get("code")
        tokenURL := fmt.Sprintf("%s?client_id=%s&client_secret=%s&code=%s",
            githubTokenURL, config.GithubClientID, config.GithubClientSecret, code)

        resp, err := http.PostForm(tokenURL, url.Values{})
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer resp.Body.Close()

        respBody, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        values, err := url.ParseQuery(string(respBody))
        if err != nil {
            http.Error(w, "Failed to parse response body", http.StatusInternalServerError)
            return
        }

        // Extract the relevant values
        accessToken := values.Get("access_token")
        //tokenType := values.Get("token_type")
        //scope := values.Get("scope")

        userInfoReq, err := http.NewRequest("GET", githubUserInfoURL, nil)
        userInfoReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
        userInfoResp, err := http.DefaultClient.Do(userInfoReq)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer userInfoResp.Body.Close()

        userInfoBody, err := ioutil.ReadAll(userInfoResp.Body)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        var user UserResponse
        if err := json.Unmarshal(userInfoBody, &user); err != nil {
            http.Error(w, "Failed to parse user info response", http.StatusInternalServerError)
            return
        }

        fmt.Println("Name:", user.Name)
        fmt.Println("Email:", user.Email)
        fmt.Println("Profile Picture URL:", user.AvatarURL)


			forum.GLogin(w,r,user.Name, user.Email, user.AvatarURL)
	
        // forum.GoogleSignUp(w,r,user.Name, user.Email, user.AvatarURL)
        // http.Redirect(w, r, "/HomePage", http.StatusFound)
    }
}



func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}

	http.HandleFunc("/auth/google/login", googleLoginHandler(config))
	http.HandleFunc("/auth/google/callback", googleCallbackHandler(config))
	http.HandleFunc("/auth/github/callback", githubCallbackHandler(config))
	http.HandleFunc("/auth/github/login", githubLoginHandler(config))
	fs := http.FileServer(http.Dir("Style"))
	http.Handle("/Style/", http.StripPrefix("/Style/", fs))

	fs2 := http.FileServer(http.Dir("Error"))
	http.Handle("/Error/", http.StripPrefix("/Error/", fs2))

	posts := http.FileServer(http.Dir("Posts"))
	http.Handle("/Posts/", http.StripPrefix("/Posts/", posts))
	profileImages := http.FileServer(http.Dir("ProfileImages"))
	http.Handle("/ProfileImages/", http.StripPrefix("/ProfileImages/", profileImages))

	http.HandleFunc("/", forum.Login)
	http.HandleFunc("/SignUp", forum.SignUpHandler)
	http.HandleFunc("/LogOut", forum.LogoutHandler)
	http.HandleFunc("/HomePage", forum.AuthMiddleware(forum.HomeHandler))
	http.HandleFunc("/CreatePost",forum.AuthMiddleware(forum.CreatePostHandler))
	http.HandleFunc("/Profile", forum.AuthMiddleware(forum.ProfileHandler))
	http.HandleFunc("/CommentHandler", forum.CommentHandler)
	http.HandleFunc("/ProfileImageHandler", forum.ProfileImageHandler)
	http.HandleFunc("/CommentLikeHandle", forum.CommentLikeHandle)
	
	forum.CreateTables()


	log.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}