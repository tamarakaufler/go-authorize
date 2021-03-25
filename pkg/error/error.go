package error

//go:generate stringer -type=Code
type Code int

const (
	SigningMethodError Code = iota + 1000
	EncodingError
	DecodingError
	ParsingJWTError
	UserMatchError
	InvalidTokenError
)
