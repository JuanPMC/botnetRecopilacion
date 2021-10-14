package main

import
(
    "net"
    "time"
    "encoding/binary"
)

type bot struct {
    uid int
    conn net.Conn
    arch string
}

func new_bot(conn net.Conn, arch string) *bot {
    return &bot{-1, conn, arch}
}

func pack_bytes(b uint16) ([]byte) {
    var tmp []byte
    tmp = make([]byte, 2)
    binary.BigEndian.PutUint16(tmp, b)
    return tmp
}

func (this *bot) handle() {
    cs.add_client(this)
    defer cs.delete_client(this)

    buf := make([]byte, 32)
    // Pack 505 into a uint16
    r := pack_bytes(505)

    for {
        this.conn.SetDeadline(time.Now().Add(180 * time.Second))
        l, err := this.conn.Read(buf)
        if err != nil || l <= 1 {
            return
        }
        l, err = this.conn.Write(r)
        if err != nil || l <= 1 {
            return
        }
    }
}