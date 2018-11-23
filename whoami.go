package ldap

import (
	"bytes"
	"errors"
	"fmt"

	ber "gopkg.in/asn1-ber.v1"
)

const (
	whoAmIOID = "1.3.6.1.4.1.4203.1.11.3"
)

type WhoAmIRequest struct {
}

func (r *WhoAmIRequest) encode() (*ber.Packet, error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Who Am I Extended Operation")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, whoAmIOID, "Extended Request Name: Who Am I OID"))
	extendedRequestValue := ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "Extended Request Value: Who Am I Request")
	whoAmIRequestValue := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Who Am I Request")

	extendedRequestValue.AppendChild(whoAmIRequestValue)
	request.AppendChild(extendedRequestValue)

	return request, nil
}

func (l *Conn) WhoAmI() ([]byte, error) {
	whoAmIRequest := &WhoAmIRequest{}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

	encodedWhoAmIRequest, err := whoAmIRequest.encode()
	if err != nil {
		return nil, err
	}
	packet.AppendChild(encodedWhoAmIRequest)

	l.Debug.PrintPacket(packet)

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	l.Debug.Printf("%d: waiting for response", msgCtx.id)
	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}

	if packet == nil {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationExtendedResponse {
		resultCode, resultDescription := getLDAPResultCode(packet)
		if resultCode != 0 {
			return nil, NewError(resultCode, errors.New(resultDescription))
		}
	} else {
		return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("Unexpected Response: %d", packet.Children[1].Tag))
	}

	extendedResponse := packet.Children[1]
	for _, child := range extendedResponse.Children {
		if child.Tag == 11 {
			return bytes.TrimPrefix(child.Data.Bytes(), []byte("u:")), nil
		}
	}

	return nil, fmt.Errorf("Server did not return expected response to whoami")
}
