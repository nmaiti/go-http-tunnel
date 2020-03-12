package sender

import "crypto/tls"

type ClientSender struct {
	Conn   *tls.Conn
	Config *tls.Config
	IdName string
}
