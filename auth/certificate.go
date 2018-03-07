package auth

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Certificates holds a collection of public certificates that are fetched from
// a given URL.  The certificates can be reloaded when the cached certs are
// expired.
type Certificates struct {
	// URL to retrieve the public certificates, meant to be initialized only once.
	URL string
	// Transport is the network transport, meant to be initialized only once.
	Transport http.RoundTripper
	// lock for the certs and the exp
	sync.RWMutex
	// certs is a map of all the public x509 certificates hosted at URL.
	certs map[int]*x509.Certificate
	// exp is the expiry time for the certificates.
	exp time.Time
}

// download certificate from userservice
func (c *Certificates) download() (map[int]*x509.Certificate, time.Duration, error) {
	log.Println("download")
	if c.Transport == nil {
		c.Transport = http.DefaultTransport
	}
	var httpClient http.Client
	req, err := http.NewRequest(http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, 0, err
	}
	// add header
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept", "application/vnd.vmware.cello.v1+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, 0, fmt.Errorf("download %s fails: %s", c.URL, resp.Status)
	}

	certs, err := c.parse(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return certs, c.cacheTime(resp), nil
}

// Parse byte array and extract certificates from it
func (c *Certificates) parse(r io.ReadCloser) (map[int]*x509.Certificate, error) {
	certArray := new([]Certs)
	if err := json.NewDecoder(r).Decode(certArray); err != nil {
		return nil, err
	}

	certs := make(map[int]*x509.Certificate)
	for k, v := range (*certArray)[0].Certs {
		block, _ := pem.Decode([]byte(v.Cert))
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs[k] = c

	}
	return certs, nil
}

// cacheTime extracts the cache time from the HTTP response header.
// A default cache time is returned if extraction fails.
func (c *Certificates) cacheTime(resp *http.Response) time.Duration {
	log.Println("cacheTime")
	cc := strings.Split(resp.Header.Get(cacheHeader), ",")
	const maxAge = "max-age="
	for _, ch := range cc {
		ch = strings.TrimSpace(ch)
		if strings.HasPrefix(ch, maxAge) {
			if d, err := strconv.Atoi(ch[len(maxAge):]); err == nil {
				t := time.Duration(d) * time.Second

				return t
			}
		}
	}

	return defaultCertsCacheTime
}

func (c *Certificates) ensureLoaded() error {
	log.Println("ensureLoaded")
	if c.exp.After(time.Now()) {
		// skip if the cached certs have not yet expired
		log.Println("skip cached certs", "c.exp", c.exp, "time.Now()", time.Now())
		return nil
	}

	certs, cacheTime, err := c.download()

	if err != nil {
		log.Println("error downloading cert", "err", err)
		return err
	}

	c.Lock()
	c.certs = certs
	c.exp = time.Now().Add(cacheTime)
	c.Unlock()

	return nil
}

// Cert returns the public certificate for the given key ID.
func (c *Certificates) Cert(kid int) (*x509.Certificate, error) {
	log.Println("Cert")
	if err := c.ensureLoaded(); err != nil {

		return nil, err
	}
	c.RLock()
	defer c.RUnlock()
	if len(c.certs) < kid {
		return nil, ErrCertificateNotFoundForKey
	}
	cert := c.certs[kid]

	return cert, nil
}

func (c *Certificates) validateToken(idToken string) (*jwt.Token, error) {
	log.Println("validateToken")
	token, err := jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		cert, err := c.Cert(0)
		if err != nil {
			log.Println("error getting cert", "err", err)
			return nil, err
		}
		return cert.PublicKey, nil
	})

	if err != nil {
		log.Println("error decoding token", "err", err, "token", token)

		if e, ok := err.(*jwt.ValidationError); ok {
			if e.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, ErrTokenExpired
			}
		}
		return nil, err
	}

	if token != nil && token.Valid == true {
		return token, nil
	}

	log.Println("token not valid", "err", err, "token", token)
	return nil, ErrTokenNotValid
}
