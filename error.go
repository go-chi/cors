package cors

import "fmt"

// Error is an interface for CORS errors.
type Error interface {
	CorsError()
}

// PreflightError is an interface for preflight errors.
type PreflightError interface {
	PreflightCorsError()
}

// ActualRequestError is an interface for actual request errors.
type ActualRequestError interface {
	ActualRequestCorsError()
}

// PreflightNotOptionMethodError is returned when the method is not allowed.
type PreflightNotOptionMethodError struct {
	Method string
}

func (e *PreflightNotOptionMethodError) Error() string {
	return fmt.Sprintf("Preflight aborted: %s!=OPTIONS", e.Method)
}

// Is implements the Is method of the error interface.
func (e *PreflightNotOptionMethodError) Is(target error) bool {
	_, ok := target.(*PreflightNotOptionMethodError)
	return ok
}

// As implements the As method of the error interface.
func (e *PreflightNotOptionMethodError) As(target interface{}) bool {
	switch target.(type) {
	case **PreflightNotOptionMethodError:
		return true
	default:
		return false
	}
}

// PreflightCorsError implements the PreflightCorsError interface.
func (e *PreflightNotOptionMethodError) PreflightCorsError() {}

// CorsError implements the CorsError interface.
func (e *PreflightNotOptionMethodError) CorsError() {}

// PreflightNotOriginAllowedError is returned when the origin is not allowed.
type PreflightNotOriginAllowedError struct {
	Origin string
}

func (e *PreflightNotOriginAllowedError) Error() string {
	return fmt.Sprintf("Preflight aborted: origin '%s' not allowed", e.Origin)
}

// Is implements the Is method of the error interface.
func (e *PreflightNotOriginAllowedError) Is(target error) bool {
	_, ok := target.(*PreflightNotOriginAllowedError)
	return ok
}

// As implements the As method of the error interface.
func (e *PreflightNotOriginAllowedError) As(target interface{}) bool {
	switch target.(type) {
	case **PreflightNotOriginAllowedError:
		return true
	default:
		return false
	}
}

// PreflightCorsError implements the PreflightCorsError interface.
func (e *PreflightNotOriginAllowedError) PreflightCorsError() {}

// CorsError implements the CorsError interface.
func (e *PreflightNotOriginAllowedError) CorsError() {}

// PreflightEmptyOriginError is returned when the origin header is empty.
type PreflightEmptyOriginError struct{}

func (e *PreflightEmptyOriginError) Error() string {
	return "Preflight aborted: empty origin"
}

// Is implements the Is method of the error interface.
func (e *PreflightEmptyOriginError) Is(target error) bool {
	_, ok := target.(*PreflightEmptyOriginError)
	return ok
}

// As implements the As method of the error interface.
func (e *PreflightEmptyOriginError) As(target interface{}) bool {
	switch target.(type) {
	case **PreflightEmptyOriginError:
		return true
	default:
		return false
	}
}

// PreflightCorsError implements the PreflightCorsError interface.
func (e *PreflightEmptyOriginError) PreflightCorsError() {}

// CorsError implements the CorsError interface.
func (e *PreflightEmptyOriginError) CorsError() {}

// PreflightNotAllowedMethodError is returned when the method is not allowed.
type PreflightNotAllowedMethodError struct {
	RequestMethod string
}

func (e *PreflightNotAllowedMethodError) Error() string {
	return fmt.Sprintf("Preflight aborted: method '%s' not allowed", e.RequestMethod)
}

// Is implements the Is method of the error interface.
func (e *PreflightNotAllowedMethodError) Is(target error) bool {
	_, ok := target.(*PreflightNotAllowedMethodError)
	return ok
}

// As implements the As method of the error interface.
func (e *PreflightNotAllowedMethodError) As(target interface{}) bool {
	switch target.(type) {
	case **PreflightNotAllowedMethodError:
		return true
	default:
		return false
	}
}

// PreflightCorsError implements the PreflightCorsError interface.
func (e *PreflightNotAllowedMethodError) PreflightCorsError() {}

// CorsError implements the CorsError interface.
func (e *PreflightNotAllowedMethodError) CorsError() {}

// PreflightNotHeadersAllowedError is returned when the headers are not allowed.
type PreflightNotHeadersAllowedError struct {
	RequestHeaders []string
}

func (e *PreflightNotHeadersAllowedError) Error() string {
	return fmt.Sprintf("Preflight aborted: headers '%v' not allowed", e.RequestHeaders)
}

// Is implements the Is method of the error interface.
func (e *PreflightNotHeadersAllowedError) Is(target error) bool {
	_, ok := target.(*PreflightNotHeadersAllowedError)
	return ok
}

// As implements the As method of the error interface.
func (e *PreflightNotHeadersAllowedError) As(target interface{}) bool {
	switch target.(type) {
	case **PreflightNotHeadersAllowedError:
		return true
	default:
		return false
	}
}

// PreflightCorsError implements the PreflightCorsError interface.
func (e *PreflightNotHeadersAllowedError) PreflightCorsError() {}

// CorsError implements the CorsError interface.
func (e *PreflightNotHeadersAllowedError) CorsError() {}

// ActualMissingOriginError is returned when the origin header is missing.
type ActualMissingOriginError struct{}

func (e *ActualMissingOriginError) Error() string {
	return "Actual request no headers added: missing origin"
}

// Is implements the Is method of the error interface.
func (e *ActualMissingOriginError) Is(target error) bool {
	_, ok := target.(*ActualMissingOriginError)
	return ok
}

// As implements the As method of the error interface.
func (e *ActualMissingOriginError) As(target interface{}) bool {
	switch target.(type) {
	case **ActualMissingOriginError:
		return true
	default:
		return false
	}
}

// ActualRequestCorsError implements the ActualRequestCorsError interface.
func (e *ActualMissingOriginError) ActualRequestCorsError() {}

// CorsError implements the CorsError interface.
func (e *ActualMissingOriginError) CorsError() {}

// ActualOriginNotAllowedError is returned when the origin is not allowed.
type ActualOriginNotAllowedError struct {
	Origin string
}

func (e *ActualOriginNotAllowedError) Error() string {
	return fmt.Sprintf("Actual request no headers added: origin '%s' not allowed", e.Origin)
}

// Is implements the Is method of the error interface.
func (e *ActualOriginNotAllowedError) Is(target error) bool {
	_, ok := target.(*ActualOriginNotAllowedError)
	return ok
}

// As implements the As method of the error interface.
func (e *ActualOriginNotAllowedError) As(target interface{}) bool {
	switch target.(type) {
	case **ActualOriginNotAllowedError:
		return true
	default:
		return false
	}
}

// ActualRequestCorsError implements the ActualRequestCorsError interface.
func (e *ActualOriginNotAllowedError) ActualRequestCorsError() {}

// CorsError implements the CorsError interface.
func (e *ActualOriginNotAllowedError) CorsError() {}

// ActualMethodNotAllowedError is returned when the method is not allowed.
type ActualMethodNotAllowedError struct {
	RequestMethod string
}

func (e *ActualMethodNotAllowedError) Error() string {
	return fmt.Sprintf("Actual request no headers added: method '%s' not allowed", e.RequestMethod)
}

// Is implements the Is method of the error interface.
func (e *ActualMethodNotAllowedError) Is(target error) bool {
	_, ok := target.(*ActualMethodNotAllowedError)
	return ok
}

// As implements the As method of the error interface.
func (e *ActualMethodNotAllowedError) As(target interface{}) bool {
	switch target.(type) {
	case **ActualMethodNotAllowedError:
		return true
	default:
		return false
	}
}

// ActualRequestCorsError implements the ActualRequestCorsError interface.
func (e *ActualMethodNotAllowedError) ActualRequestCorsError() {}

// CorsError implements the CorsError interface.
func (e *ActualMethodNotAllowedError) CorsError() {}
