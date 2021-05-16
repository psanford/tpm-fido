package statuscode

// status codes from section 3.3 of
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html

const (
	NoError                = 0x9000 // The command completed successfully without error.
	ConditionsNotSatisfied = 0x6985 // The request was rejected due to test-of-user-presence being required.
	WrongData              = 0x6A80 // The request was rejected due to an invalid key handle.
	WrongLength            = 0x6700 // The length of the request was invalid
	ClaNotSupported        = 0x6E00 // The Class byte of the request is not supported
	InsNotSupported        = 0x6D00 // The Instruction of the request is not supported
)
