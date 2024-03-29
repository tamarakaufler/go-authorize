package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	//"github.com/dgrijalva/jwt-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"

	authErr "github.com/tamarakaufler/go-authorize/pkg/error"
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
		authErr.EncodeError(w, err, authErr.EncodingError)
		return
	}

	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", tokS))
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(JWTToken{
		Token:     tokS,
		TokenType: "Bearer",
		ExpiresIn: expiresAt,
	})
	if err != nil {
		authErr.EncodeError(w, err, authErr.EncodingError)
		return
	}
}

//nolint:nestif
// tokenValidation is middleware asserting validity of the JWL token.
func tokenValidation(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				tok, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					_, ok := token.Method.(*jwt.SigningMethodHMAC)
					if !ok {
						return nil, errors.New(
							authErr.SigningMethodError.String() + " " + strconv.Itoa(int(authErr.SigningMethodError)))
					}
					return []byte("secret"), nil
				})
				if err != nil {
					authErr.EncodeError(w, err, authErr.ParsingJWTError)
					return
				}
				if tok.Valid {
					var user User
					err := mapstructure.Decode(tok.Claims, &user)
					if err != nil {
						authErr.EncodeError(w, err, authErr.DecodingError)
						return
					}
					vars := mux.Vars(req)
					userN := vars["username"]
					if userN != user.Username {
						authErr.EncodeError(w, err, authErr.UserMatchError)
						return
					}

					context.Set(req, "claims", tok.Claims)
					next(w, req)
					return
				}
				authErr.EncodeError(w, err, authErr.InvalidTokenError)
				return
			}
			authErr.EncodeError(w, errors.New("bearer token length incorrect"), authErr.InvalidTokenError)
			return
		}
		authErr.EncodeError(w, errors.New("missing authorization header"), authErr.MissingAuthHeaderError)
	})
}

// users
func users(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "claims")
	var user User

	err := mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	if err != nil {
		authErr.EncodeError(w, err, authErr.InvalidTokenError)
		return
	}

	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		authErr.EncodeError(w, err, authErr.InvalidTokenError)
		return
	}
}

func main() {
	host := ":8888"
	fmt.Printf("\nApplication Starting: %s...\n\n", host)

	router := mux.NewRouter()
	router.HandleFunc("/authorize", authHandler).Methods("POST")
	router.HandleFunc("/users/{username}/articles", tokenValidation(users)).Methods("GET")

	if err := http.ListenAndServe(host, router); err != http.ErrServerClosed {
		log.Fatalf("error while listening: %s\n", err.Error())
	}
}
