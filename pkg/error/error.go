package error

//go:generate stringer -type=Code
type Code int

const (
	SigningMethod Code = iota + 1000
	ParsingJWT
	UserMatch
	InvalidToken
)
