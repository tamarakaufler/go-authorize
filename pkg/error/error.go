package error

import (
	"encoding/json"
	"io"
)

// Error contains error message.
type Error struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    Code   `json:"code"`
}

//go:generate stringer -type=Code
type Code int

const (
	SigningMethodError Code = iota + 1000
	MissingAuthHeaderError
	ParsingJWTError
	UserMatchError
	InvalidTokenError
	EncodingError
	DecodingError
)

func EncodeError(w io.Writer, err error, code Code) error {
	return json.NewEncoder(w).Encode(
		Error{
			Message: err.Error(),
			Type:    code.String(),
			Code:    code,
		},
	)
}
