package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
)

// User holds authentication details.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTToken holds any desired user information.
type JWTToken struct {
	TokenType string `json:"token_type"`
	Token     string `json:"access_token"`
	ExpiresIn int64  `json:"expires_in"`
}

// JWTTokenClaims contain JWT standard information together with any custom data.
type JWTTokenClaims struct {
	*jwt.StandardClaims
	User
}

// Error contains error message.
type Error struct {
	Message string `json:"message"`
}

// authHandler is fired when authenticating a user, using the POST
// request body (username, password) to verify the user.
func authHandler(w http.ResponseWriter, req *http.Request) {
	var user User
	_ = json.NewDecoder(req.Body).Decode(&user)

	expiresAt := time.Now().Add(time.Second * 10).Unix()

	tok := jwt.New(jwt.SigningMethodHS256)
	tok.Claims = &JWTTokenClaims{
		&jwt.StandardClaims{
			ExpiresAt: expiresAt,
		},
		User{
			user.Username,
			user.Password,
		},
	}

	tokS, err := tok.SignedString([]byte("secret"))
	if err != nil {
		fmt.Fprint(w, "error occurred during authentication")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JWTToken{
		Token:     tokS,
		TokenType: "Bearer",
		ExpiresIn: expiresAt,
	})
}

func tokenValidationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				tok, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, errors.New("error while parsing JWT")
					}
					return []byte("secret"), nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(Error{Message: error.Error()})
					return
				}
				if tok.Valid {
					var user User
					mapstructure.Decode(tok.Claims, &user)

					vars := mux.Vars(req)
					userN := vars["username"]
					if userN != user.Username {
						json.NewEncoder(w).Encode(Error{Message: "invalid token - username does not match"})
						return
					}

					context.Set(req, "claims", tok.Claims)
					next(w, req)
					return
				}
				json.NewEncoder(w).Encode(Error{Message: "invalid token"})
				return
			}
			json.NewEncoder(w).Encode(Error{Message: "invalid token"})
			return
		}
		json.NewEncoder(w).Encode(Error{Message: "authorization header required"})
	})
}

func users(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "claims")
	var user User
	mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	json.NewEncoder(w).Encode(user)
}

func main() {
	host := ":8888"
	fmt.Printf("\nApplication Starting: %s...\n\n", host)

	router := mux.NewRouter()
	router.HandleFunc("/authenticate", authHandler).Methods("POST")
	router.HandleFunc("/users/{username}/creds", tokenValidationMiddleware(users)).Methods("GET")

	if err := http.ListenAndServe(":8888", router); err != http.ErrServerClosed {
		log.Fatalf("error while listening: %s\n", err.Error())
	}
}
