package handler

import (
	"bytes"
	"encoding/json"
	"errors"
)

type requestString string

func (s *requestString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("string field must not be null")
	}
	return json.Unmarshal(data, (*string)(s))
}
