package spec

import (
	"errors"
	"fmt"
)

// FieldError ties a validation failure to the form field it came from, so the UI can show it where the mistake is.
// Path is relative to the object being validated: dots for nesting, numbers for list items (options.t_routes.0.target).
type FieldError struct {
	Path string
	Msg  string
}

func (e *FieldError) Error() string { return e.Msg }

// Invalid builds a FieldError.
func Invalid(path, format string, args ...any) error {
	return &FieldError{Path: path, Msg: fmt.Sprintf(format, args...)}
}

// FieldOf digs the field and the plain message out of err, however deeply it was wrapped.
func FieldOf(err error) (path, msg string, ok bool) {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Path, fe.Msg, true
	}
	return "", err.Error(), false
}
