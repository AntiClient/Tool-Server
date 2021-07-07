package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"crypto/sha256"
	"github.com/dchest/pbkdf2"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"errors"
	"net/http"
	"os"
	"strings"
)

func encrypt(key []byte, text string) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil { 
        return "", err
    }

    msg := text
    ciphertext := make([]byte, aes.BlockSize+len(msg))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
    finalMsg := (base64.URLEncoding.EncodeToString(ciphertext))
    return finalMsg, nil
}

func decrypt(key []byte, text string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decodedMsg, err := base64.URLEncoding.DecodeString((text))
	if err != nil {
		return nil, err
	}

	if len(decodedMsg) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	return (msg), nil
}

func GetDataFromPin(pin string) string {
	url := string("http://api.anticlient.xyz/login.php?pin=" + pin)
	response, err := http.Get(url)

	if err != nil {
		fmt.Println(err)
		return ""
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	var sessionCookie string
	for _, cookie := range response.Cookies() {
        if cookie.Name == "PHPSESSID" {
			sessionCookie = cookie.Value
        }
    }

	if err != nil {
		fmt.Println(err)
		return ""
	}

	return string(contents) + ":" + sessionCookie
}

func IsSessionValid(sid string) bool {
	url := string("https://api.anticlient.xyz/checksession.php?SID=" + sid)
	response, err := http.Get(url)

	if err != nil {
		fmt.Println(err)
		return false
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	fmt.Println(string(contents))

	if err != nil {
		fmt.Println(err)
		return false
	}
	return len(contents) == 0 
}

func main() {
	log.SetFlags(log.LstdFlags)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/client_data/", func(w http.ResponseWriter, req *http.Request) {
		pin := req.URL.Query().Get("pin")
		if len(pin) == 0 {
			w.Write([]byte("Invalid Pin Length"))
			return
		}
              
		data := GetDataFromPin(pin)
              
		if len(data) == 0 {
			w.Write([]byte("Invalid Pin"))
			return
		}
		
		username := strings.Split(data, ":")[0]
		cookie := strings.Split(data, ":")[1]
		

		if !IsSessionValid(cookie) {
			w.Write([]byte("Invalid Session"))
			return
		}

		log.Println("Successfuly Validated Pin For User: " + username)
		

		buf := bytes.NewBuffer(nil)
		f, err := os.Open("client_data.json")
		if err != nil {
			fmt.Println(err)
			return
		}
		io.Copy(buf, f)
		f.Close()
		s := buf.Bytes()

		var m map[string]interface{}
		json.Unmarshal([]byte(s), &m)
               
		m["username"] = username
		m["SID"] = cookie
		new_data, err := json.Marshal(m)

		if err != nil {
			fmt.Println(err)
			return
		}

	   nigger_salt := []byte{ 0x51, 0x4a, 0x39, 0x70, 0x9d, 0x6f, 0x50, 0x9f,
                      0x6e, 0x2f, 0x7c, 0x36, 0xcf, 0xc3, 0xa0, 0xf6,
                      0xca, 0x4d, 0x97, 0x1, 0x43, 0x75, 0x90, 0x41,
                      0x48, 0x31, 0xbf, 0xcb, 0xa2, 0x10, 0xbe, 0x5b }
	   key := pbkdf2.WithHMAC(sha256.New, []byte(pin), nigger_salt, 2520, 32)
		
		encrypted, err := encrypt(key, string(new_data))

		if err != nil {
			fmt.Print(err)
			return
		}

		w.Write([]byte(encrypted))
	})
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}
