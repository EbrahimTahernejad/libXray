package xray

import (
	"github.com/GFW-knocker/Xray-core/common/uuid"
)

// convert text to uuid
func CustomUUID(text string) string {
	id, err := uuid.ParseString(text)
	if err != nil {
		return text
	}
	return id.String()
}
