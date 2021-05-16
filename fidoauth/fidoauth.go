// fidoauth implements the fido1 authentication API
package fidoauth

import (
	"fmt"
)

const (
	CmdRegister     = 0x01
	CmdAuthenticate = 0x02
	CmdVersion      = 0x03

	CtrlCheckOnly                     AuthCtrl = 0x07 // Check if the provided key is valid
	CtrlEnforeUserPresenceAndSign     AuthCtrl = 0x03 // confirm with user then sign
	CtrlDontEnforeUserPresenceAndSign AuthCtrl = 0x08 // just sign without confirming
)

type AuthenticatorRequest struct {
	Command uint8
	Param1  uint8
	Param2  uint8
	Size    int
	Data    []byte

	Register     *AuthenticatorRegisterReq
	Authenticate *AuthenticatorAuthReq
}

type AuthenticatorRegisterReq struct {
	ChallengeParam   [32]byte
	ApplicationParam [32]byte
}

type AuthenticatorResponse struct {
	Data   []byte
	Status uint16
}

type AuthCtrl uint8

type AuthenticatorAuthReq struct {
	Ctrl             AuthCtrl
	ChallengeParam   [32]byte
	ApplicationParam [32]byte
	KeyHandle        []byte
}

func DecodeAuthenticatorRequest(raw []byte) (*AuthenticatorRequest, error) {
	if len(raw) < 7 {
		return nil, fmt.Errorf("authenticator request too short")
	}

	req := AuthenticatorRequest{
		Command: raw[1],
		Param1:  raw[2],
		Param2:  raw[3],
		Size:    (int(raw[4]) << 16) | (int(raw[5]) << 8) | int(raw[6]),
		Data:    raw[7:],
	}

	if req.Command == CmdRegister {
		var reg AuthenticatorRegisterReq
		if len(req.Data) < len(reg.ChallengeParam)+len(reg.ApplicationParam) {
			return nil, fmt.Errorf("register request incorrect size: %d", len(req.Data))
		}

		copy(reg.ChallengeParam[:], req.Data[:32])
		copy(reg.ApplicationParam[:], req.Data[32:])
		req.Register = &reg
	} else if req.Command == CmdAuthenticate {
		var auth AuthenticatorAuthReq

		if len(req.Data) < len(auth.ChallengeParam)+len(auth.ApplicationParam)+2 {
			return nil, fmt.Errorf("authenticate request too small: %d", len(req.Data))
		}

		auth.Ctrl = AuthCtrl(req.Param1)

		switch auth.Ctrl {
		case CtrlCheckOnly, CtrlEnforeUserPresenceAndSign, CtrlDontEnforeUserPresenceAndSign:
		default:
			return nil, fmt.Errorf("unknown ctrl type: %02x", auth.Ctrl)
		}

		data := req.Data
		copy(auth.ChallengeParam[:], data[:32])
		data = data[32:]

		copy(auth.ApplicationParam[:], data[:32])
		data = data[32:]

		khLen := data[0]
		data = data[1:]

		if len(data) < int(khLen) {
			return nil, fmt.Errorf("key handle len too short %d vs %d", len(data), int(khLen))
		}

		auth.KeyHandle = data[:khLen]
		req.Authenticate = &auth
	}

	return &req, nil
}
