package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

type Client struct {
	Socket string
}

func (c *Client) Send(req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.Socket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.Socket, err)
	}
	defer conn.Close()
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
