//	Simple twitter client
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	baseURL     = "https://api.twitter.com/1.1"
	templateStr = `
	<html>
	<head>
	</head>
	<body>
	{{if .}}
		{{.}}
	{{end}}
	<form action="/" name=f method="POST">
		<p><textarea maxLength=140  name=status  style="width: 20em; height: 10em" ></textarea></p>
		<p><input type=submit value="send" name=qr></p>
	</form>
	</body>
	</html>
	`
)

type Credentials struct {
	ConsumerKey    string
	ConsumerSecret string
	Token          string
	Secret         string
}

type keyValue struct{ key, value []byte }
type byKeyValue []keyValue

var port = flag.String("port", "1718", "service port")
var templ = template.Must(template.New("qr").Parse(templateStr))
var nonceCounter uint64
var oauthKeys = []string{
	"oauth_consumer_key",
	"oauth_nonce",
	"oauth_signature",
	"oauth_signature_method",
	"oauth_timestamp",
	"oauth_token",
	"oauth_version",
}

// noscape[b] is true if b should not be escaped per section 3.6 of the RFC.
var noEscape = [256]bool{
	'A': true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
	'a': true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
	'0': true, true, true, true, true, true, true, true, true, true,
	'-': true,
	'.': true,
	'_': true,
	'~': true,
}

func init() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	//	set env variables
	f, err := os.Open(".env")
	if err != nil {
		log.Println(err)
		return
	}

	input := bufio.NewScanner(f)
	for input.Scan() {
		v := strings.TrimSpace(input.Text())
		if len(v) < 1 {
			continue
		}

		vs := strings.Split(v, "=")
		if len(vs) != 2 {
			log.Printf("Invalid env variable (%s)", v)
			continue
		}

		os.Setenv(vs[0], vs[1])
	}

	f.Close()

	//port
	p := ":" + *port
	port = &p
}

func main() {
	http.Handle("/", http.HandlerFunc(do))
	err := http.ListenAndServe(*port, nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}

func do(w http.ResponseWriter, req *http.Request) {
	var httpStatus string
	var err error
	if status := req.FormValue("status"); len(status) > 1 {
		httpStatus, err = send(status)
		if err != nil {
			httpStatus = "500 Internal Server Error"
		}
	}

	templ.Execute(w, httpStatus)
}

func send(status string) (httpStatus string, err error) {
	form := url.Values{}
	form.Set("status", status)
	urlStr := baseURL + "/statuses/update.json"
	client := http.DefaultClient
	method := "POST"
	signatureMethod := "HMAC-SHA1"
	credentials := Credentials{
		ConsumerKey:    os.Getenv("CONSUMER_KEY"),
		ConsumerSecret: os.Getenv("CONSUMER_SECRET"),
		Token:          os.Getenv("TOKEN"),
		Secret:         os.Getenv("SECRET"),
	}

	req, err := http.NewRequest(method, urlStr, strings.NewReader(form.Encode()))
	if err != nil {
		log.Println(err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	p, err := oauthParams(&credentials, method, signatureMethod, req.URL, form)
	if err != nil {
		log.Println(err)
		return
	}

	var h []byte
	for _, k := range oauthKeys {
		if v, ok := p[k]; ok {
			if h == nil {
				h = []byte(`OAuth `)
			} else {
				h = append(h, ", "...)
			}
			h = append(h, k...)
			h = append(h, `="`...)
			h = append(h, encode(v, false)...)
			h = append(h, '"')
		}
	}

	req.Header.Set("Authorization", string(h))

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()
	httpStatus = resp.Status
	return
}

func oauthParams(credentials *Credentials, method, signatureMethod string, u *url.URL, form url.Values) (map[string]string, error) {
	oauthParams := map[string]string{
		"oauth_consumer_key":     credentials.ConsumerKey,
		"oauth_signature_method": signatureMethod,
		"oauth_version":          "1.0",
		"oauth_timestamp":        strconv.FormatInt(time.Now().Unix(), 10),
		"oauth_nonce":            nonce(),
		"oauth_token":            credentials.Token,
	}

	key := encode(credentials.ConsumerSecret, false)
	key = append(key, '&')
	key = append(key, encode(credentials.Secret, false)...)
	h := hmac.New(sha1.New, key)
	writeBaseString(h, method, u, form, oauthParams) //	@todo
	oauthParams["oauth_signature"] = base64.StdEncoding.EncodeToString(h.Sum(key[:0]))
	return oauthParams, nil
}

func nonce() string {
	n := atomic.AddUint64(&nonceCounter, 1)
	if n == 1 {
		binary.Read(rand.Reader, binary.BigEndian, &n)
		n ^= uint64(time.Now().UnixNano())
		atomic.CompareAndSwapUint64(&nonceCounter, 1, n)
	}
	return strconv.FormatUint(n, 16)
}

func encode(s string, double bool) []byte {
	// Compute size of result.
	m := 3
	if double {
		m = 5
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if noEscape[s[i]] {
			n++
		} else {
			n += m
		}
	}

	p := make([]byte, n)

	// Encode it.
	j := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if noEscape[b] {
			p[j] = b
			j++
		} else if double {
			p[j] = '%'
			p[j+1] = '2'
			p[j+2] = '5'
			p[j+3] = "0123456789ABCDEF"[b>>4]
			p[j+4] = "0123456789ABCDEF"[b&15]
			j += 5
		} else {
			p[j] = '%'
			p[j+1] = "0123456789ABCDEF"[b>>4]
			p[j+2] = "0123456789ABCDEF"[b&15]
			j += 3
		}
	}
	return p
}

func writeBaseString(w io.Writer, method string, u *url.URL, form url.Values, oauthParams map[string]string) {
	// Method
	w.Write(encode(strings.ToUpper(method), false))
	w.Write([]byte{'&'})

	// URL
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	uNoQuery := *u
	uNoQuery.RawQuery = ""
	path := uNoQuery.RequestURI()

	switch {
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = host[:len(host)-len(":80")]
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = host[:len(host)-len(":443")]
	}

	w.Write(encode(scheme, false))
	w.Write(encode("://", false))
	w.Write(encode(host, false))
	w.Write(encode(path, false))
	w.Write([]byte{'&'})

	// Create sorted slice of encoded parameters. Parameter keys and values are
	// double encoded in a single step. This is safe because double encoding
	// does not change the sort order.
	queryParams := u.Query()
	p := make(byKeyValue, 0, len(form)+len(queryParams)+len(oauthParams))
	p = p.appendValues(form)
	p = p.appendValues(queryParams)
	for k, v := range oauthParams {
		p = append(p, keyValue{encode(k, true), encode(v, true)})
	}
	sort.Sort(p)

	// Write the parameters.
	encodedAmp := encode("&", false)
	encodedEqual := encode("=", false)
	sep := false
	for _, kv := range p {
		if sep {
			w.Write(encodedAmp)
		} else {
			sep = true
		}
		w.Write(kv.key)
		w.Write(encodedEqual)
		w.Write(kv.value)
	}
}

func (p byKeyValue) Len() int {
	return len(p)
}

func (p byKeyValue) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p byKeyValue) Less(i, j int) bool {
	sgn := bytes.Compare(p[i].key, p[j].key)
	if sgn == 0 {
		sgn = bytes.Compare(p[i].value, p[j].value)
	}
	return sgn < 0
}

func (p byKeyValue) appendValues(values url.Values) byKeyValue {
	for k, vs := range values {
		k := encode(k, true)
		for _, v := range vs {
			v := encode(v, true)
			p = append(p, keyValue{k, v})
		}
	}
	return p
}
