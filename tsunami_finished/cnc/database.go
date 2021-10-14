package main

import
(
    "database/sql"
    "fmt"
    //"net"
    //"encoding/binary"
    _ "github.com/go-sql-driver/mysql"
)

type database struct {
    db *sql.DB
}

type acc_info struct {
    username string
    max_bots int
    admin int
    logged_in int
    max_time int
    flood_cooldown uint32
}

func new_db(db_addr string, db_user string, db_password string, db_name string) *database {
    db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", db_user, db_password, db_addr, db_name))
    if err != nil {
        fmt.Println(err)
    }
    return &database{db}
}

func (this *database) try_auth(username string, password string) (bool, acc_info) {
    rows, err := this.db.Query("SELECT username, max_bots, admin, logged_in, max_time, flood_cooldown FROM users WHERE username = ? AND password = ?", username, password)
    if err != nil {
        fmt.Println(err)
        return false, acc_info{"", 0, 0, 0, 0, 0}
    }
    defer rows.Close()
    if !rows.Next() {
        return false, acc_info{"", 0, 0, 0, 0, 0}
    }
    var info acc_info
    rows.Scan(&info.username, &info.max_bots, &info.admin, &info.logged_in, &info.max_time, &info.flood_cooldown)
    return true, info
}
 
func (this *database) update_logged_in(username string, l int) {
    _, err := this.db.Query("UPDATE users SET logged_in = ? WHERE username = ?", l, username)
    if err != nil {
        fmt.Println(err)
        return
    }
    return
}

func (this *database) can_flood(username string, duration uint32, flood_cooldown uint32, max_bots int, command string, targets string, port uint16) error {
    return nil
}

func (this *database) flush_logged_in() {
    rows, err := this.db.Query("SELECT username FROM users")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer rows.Close()
    var ar []string
    i := 0
    // No way we exceed anymore than 128 registered usernames in the database
    ar = make([]string, 128)
    for rows.Next() {
        var name string
        rows.Scan(&name)
        ar[i] = name
        i++
    }
    if i == 0 {
        return
    }
    // Dump out the usernames and reset the logged in data
    for j := 0; j < i; j++ {
        db.update_logged_in(ar[j], 0)
    }
    return
}

func (this *database) dump_admin(username string) (int) {
    rows, err := this.db.Query("SELECT admin FROM users WHERE username = ?", username)
    if err != nil {
        fmt.Println(err)
        return -1
    }
    defer rows.Close()
    if !rows.Next() {
        return -1
    }
    var admin int
    rows.Scan(&admin)
    return admin
}