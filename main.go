package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fanzhangio/segmentproxy/auth"
	"github.com/go-openapi/errors"
	"github.com/gorilla/handlers"
	"github.com/tylerb/graceful"
)

const (
	endpoint = "https://auth.fanzhang.io"
)

var port = flag.String("port", "443", "bind address port")
var scheme = flag.String("scheme", "https", "specify scheme : http or https")
var debug = flag.Bool("debug", false, "debug mode, skipping authentication")
var key = flag.String("key", "", "Segment key")
var certs = flag.String("certs", "", "TLS certificates")
var pkey = flag.String("pkey", "", "TLS private key")
var jwtToken = http.CanonicalHeaderKey("LCM_JWTTOKEN")

func main() {
	flag.Parse()
	var wg sync.WaitGroup
	getSchemePort()
	if err := getSegmentKey(); err != nil {
		log.Fatal(err)
	}
	if err := getTLSCertsPrivateKey(); err != nil {
		log.Fatal(err)
	}
	cdnURL, err := url.Parse("http://cdn.segment.com")
	if err != nil {
		log.Fatal(err)
	}
	trackingAPIURL, err := url.Parse("http://api.segment.io")
	if err != nil {
		log.Fatal(err)
	}
	proxy := newSegmentReverseProxy(cdnURL, trackingAPIURL)
	if *debug {
		proxy = handlers.LoggingHandler(os.Stdout, proxy)
	}

	if strings.EqualFold(*scheme, "http") {
		httpServer := &graceful.Server{Server: new(http.Server)}
		httpServer.SetKeepAlivesEnabled(true)
		httpServer.TCPKeepAlive = 3 * time.Minute
		httpServer.Handler = authMiddleware(proxy)

		wg.Add(1)
		log.Println("Starting serving proxy server at http scheme...")
		go func() {
			defer wg.Done()
			httpListener, err := net.Listen("tcp4", ":"+*port)
			if err != nil {
				log.Fatalln(err)
			}
			if err := httpServer.Serve(httpListener); err != nil {
				log.Fatalln(err)
			}
		}()
	}

	if *scheme == "" || strings.EqualFold(*scheme, "https") {
		httpsServer := &graceful.Server{Server: new(http.Server)}
		httpsServer.SetKeepAlivesEnabled(true)
		httpsServer.TCPKeepAlive = 3 * time.Minute
		httpsServer.ListenLimit = 50
		httpsServer.Timeout = 10 * time.Second
		httpsServer.Handler = authMiddleware(proxy)
		httpsServer.Logger = graceful.DefaultLogger()
		httpsServer.TLSConfig = new(tls.Config)
		httpsServer.TLSConfig.NextProtos = []string{"http/1.1"}
		httpsServer.TLSConfig.MinVersion = tls.VersionTLS12
		httpsServer.TLSConfig.Certificates = make([]tls.Certificate, 1)
		var er error
		log.Println("Loading certificates and private key")
		httpsServer.TLSConfig.Certificates[0], er = tls.LoadX509KeyPair(*certs, *pkey)
		if er != nil {
			log.Fatalln(er)
		}
		wg.Add(1)
		log.Println("Starting serving proxy server at https scheme...")
		go func() {
			defer wg.Done()
			tlsListener, err := net.Listen("tcp4", ":"+*port)
			if err != nil {
				log.Fatalln(err)
			}
			if err = httpsServer.Serve(tls.NewListener(tlsListener, httpsServer.TLSConfig)); err != nil {
				log.Fatalln(err)
			}
		}()
	}

	wg.Wait()

}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("In authMiddleware")
		requestToken := r.Header.Get(http.CanonicalHeaderKey("Authorization"))
		if requestToken == "" {
			requestToken = r.Header.Get(jwtToken)
			r.Header.Del(jwtToken)
		}
		if len(requestToken) > 6 && strings.ToUpper(requestToken[:7]) == "BEARER " {
			requestToken = requestToken[7:]
		}
		if requestToken == "" {
			// TOTO: reject here immediately?
			log.Println("Empty requestToken")
			return
		}
		tv := auth.NewTokenVerifier(endpoint)
		if _, err := tv.Verify(requestToken); err != nil {
			if err == auth.ErrTokenExpired {
				log.Printf(errors.New(http.StatusGone, fmt.Sprintf("[Token Expired: %s]\n", err)).Error())
			} else {
				log.Printf(errors.Unauthenticated(fmt.Sprintf("[Invalid Token: %s]\n", err)).Error())
			}
		} else {
			setAuthHeader(r)
			next.ServeHTTP(w, r)
		}
	})
}

func setAuthHeader(r *http.Request) {
	log.Println("Set AuthHeader with segment key")
	r.Header.Del("Authorization")
	if *debug {
		log.Printf("...Segment Key : %s \n", *key)
	}
	r.SetBasicAuth(*key, "")
}

func newSegmentReverseProxy(cdn *url.URL, trackingAPI *url.URL) http.Handler {
	director := func(req *http.Request) {
		log.Println("In director")
		if *debug {
			b, _ := httputil.DumpRequest(req, true)
			log.Println("Request IN>>>>", string(b))
		}
		var target *url.URL
		if strings.HasPrefix(req.URL.String(), "/v1/projects") || strings.HasPrefix(req.URL.String(), "/analytics.js/v1") {
			target = cdn
		} else {
			log.Println("Using tracking")
			target = trackingAPI
		}
		targetQuery := target.RawQuery
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		req.Host = req.URL.Host
		if *debug {
			b, _ := httputil.DumpRequest(req, true)
			log.Println("Request OUT<<<<<", string(b))
		}
		log.Printf("Request Host : %s \n", req.Host)
		log.Printf("Request Path : %s \n", req.URL.Path)
	}
	l := log.New(os.Stderr, "proxy-log", log.LstdFlags)
	return &httputil.ReverseProxy{
		Director:      director,
		FlushInterval: time.Second,
		ErrorLog:      l,
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func getSegmentKey() error {
	if key == nil || *key == "" {
		*key = os.Getenv("SEGMENT_KEY")
	}
	if *key == "" {
		log.Fatal(errors.New(http.StatusUnauthorized, "Segement Key is empty"))
	}
	return nil
}

func getTLSCertsPrivateKey() error {
	if certs == nil || *certs == "" {
		*certs = os.Getenv("TLS_CERTIFICATE")
	}
	if pkey == nil || *pkey == "" {
		*pkey = os.Getenv("TLS_PRIVATE_KEY")
	}
	if *scheme == "https" && (*certs == "" || *pkey == "") {
		log.Fatal(errors.New(http.StatusUnauthorized, "certificates or private key is empty for https"))
	}
	return nil
}

func getSchemePort() {
	if *scheme == "http" && *port == "" {
		*port = "8080"
	}
}
