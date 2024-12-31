package dtlscoap

import (
	"fmt"
	"net"

	"github.com/dustin/go-coap"
	"github.com/pion/dtls"
)

// DtlsClient provides an domain-agnostic CoAP-client with DTLS transport.
type DtlsClient struct {
	conn           *dtls.Conn
	msgID          uint16
	gatewayAddress string
	clientID       string
	psk            string
}

// NewDtlsClient acts as factory function, returns a pointer to a connected (or will panic) DtlsClient.
func NewDtlsClient(gatewayAddress, clientID, psk string) *DtlsClient {
	client := &DtlsClient{
		gatewayAddress: gatewayAddress,
		clientID:       clientID,
		psk:            psk,
	}
	client.connect()
	return client
}

func (dc *DtlsClient) connect() {
	config := dtls.Config{
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8, dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		PSKIdentityHint: []byte(dc.clientID),
		PSK: func(data []byte) ([]byte, error) {
			return []byte(dc.psk), nil
		},
	}

	ip := net.ParseIP(dc.gatewayAddress)
	addr := &net.UDPAddr{
		IP:   ip,
		Port: 5684,
		Zone: "",
	}

	conn, err := dtls.Dial("udp", addr, &config)
	if err != nil {
		fmt.Println(err)
	}

	dc.conn = conn
}

// Call writes the supplied coap.Message to the peer
func (dc *DtlsClient) Call(req coap.Message) (coap.Message, error) {
	data, err := req.MarshalBinary()
	if err != nil {
		return coap.Message{}, err
	}

	_, err = dc.conn.Write(data)
	if err != nil {
		return coap.Message{}, err
	}

	out := make([]byte, 4096)
	n, err := dc.conn.Read(out)
	if err != nil {
		return coap.Message{}, err
	}

	msg, err := coap.ParseMessage(out[:n])
	if err != nil {
		return coap.Message{}, err
	}

	return msg, nil
}

// BuildGETMessage produces a CoAP GET message with the next msgID set.
func (dc *DtlsClient) BuildGETMessage(path string) coap.Message {
	dc.msgID++
	req := coap.Message{
		Type:      coap.Confirmable,
		Code:      coap.GET,
		MessageID: dc.msgID,
	}
	req.SetPathString(path)
	return req
}

//req.SetOption(coap.ETag, "weetag")
//req.SetOption(coap.MaxAge, 3)

// BuildPUTMessage produces a CoAP PUT message with the next msgID set.
func (dc *DtlsClient) BuildPUTMessage(path string, payload string) coap.Message {
	dc.msgID++

	req := coap.Message{
		Type:      coap.Confirmable,
		Code:      coap.PUT,
		MessageID: dc.msgID,
		Payload:   []byte(payload),
	}
	req.SetPathString(path)

	return req
}

// BuildPOSTMessage produces a CoAP POST message with the next msgID set.
func (dc *DtlsClient) BuildPOSTMessage(path string, payload string) coap.Message {
	dc.msgID++

	req := coap.Message{
		Type:      coap.Confirmable,
		Code:      coap.POST,
		MessageID: dc.msgID,
		Payload:   []byte(payload),
	}
	req.SetPathString(path)

	return req
}
