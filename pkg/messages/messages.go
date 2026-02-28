package messages

import (
	"errors"
	"fmt"
)

type Message struct {
	Header
	Sign1 *Sign1
	Sign2 *Sign2
}

var ErrInvalidMessage = errors.New("invalid message")

type MessageType uint8

// MessageType s must be increasing.
const (
	MessageTypeNone MessageType = iota
	MessageTypeSign1
	MessageTypeSign2
)

func (m *Message) BytesAppend(existing []byte) (data []byte, err error) {
	existing, err = m.Header.BytesAppend(existing)
	if err != nil {
		return nil, fmt.Errorf("message.BytesAppend: %w", err)
	}

	switch m.Type {
	case MessageTypeSign1:
		if m.Sign1 != nil {
			return m.Sign1.BytesAppend(existing)
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			return m.Sign2.BytesAppend(existing)
		}
	}

	return nil, errors.New("message does not contain any data")
}

func (m *Message) Size() int {
	var size int
	switch m.Type {
	case MessageTypeSign1:
		if m.Sign1 != nil {
			size = m.Sign1.Size()
		}
	case MessageTypeSign2:
		if m.Sign2 != nil {
			size = m.Sign2.Size()
		}
	}
	return m.Header.Size() + size
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *Message) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, m.Size())
	return m.BytesAppend(buf)
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *Message) UnmarshalBinary(data []byte) error {
	var err error

	if err = m.Header.UnmarshalBinary(data); err != nil {
		return err
	}
	data = data[m.Header.Size():]

	switch m.Type {
	case MessageTypeSign1:
		var sign1 Sign1
		if err = sign1.UnmarshalBinary(data); err == nil {
			m.Sign1 = &sign1
		}
	case MessageTypeSign2:
		var sign2 Sign2
		if err = sign2.UnmarshalBinary(data); err == nil {
			m.Sign2 = &sign2
		}
	default:
		return errors.New("messages.UnmarshalBinary: invalid message type")
	}

	return nil
}

func (m *Message) Equal(other interface{}) bool {
	otherMsg, ok := other.(*Message)
	if !ok {
		return false
	}

	if !m.Header.Equal(otherMsg.Header) {
		return false
	}

	switch m.Type {
	case MessageTypeSign1:
		if m.Sign1 != nil && otherMsg.Sign1 != nil {
			return m.Sign1.Equal(otherMsg.Sign1)
		}
	case MessageTypeSign2:
		if m.Sign2 != nil && otherMsg.Sign2 != nil {
			return m.Sign2.Equal(otherMsg.Sign2)
		}
	}
	return false
}
