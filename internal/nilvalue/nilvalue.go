// Package nilvalue identifies nil interfaces and their nil dynamic values.
package nilvalue

import "reflect"

// IsNil reports whether v is nil or holds a nil pointer or nil function, without
// calling methods. A nil map, slice or channel is not reported: methods on those
// types can be valid on the nil value, while a nil pointer or function fails
// when it is used.
func IsNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}
