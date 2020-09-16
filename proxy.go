package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

func SessionMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			cookie, err := req.Cookie("ID")

			if err != nil {
				uid := uuid.New()
				cookie = &http.Cookie{SameSite: http.SameSiteDefaultMode, Name: "ID", Value: uid.String()}
				http.SetCookie(w, cookie)

			}
			if cookie != nil {
				ctx := context.WithValue(req.Context(), "ID", cookie.Value)
				req = req.WithContext(ctx)
			}

			next.ServeHTTP(w, req)
		})
	}
}

type ProxyDelivery struct {
	rep Repository
}

func NewProxyDelivery() (ProxyDelivery, error) {
	rep, err := NewRepository()
	if err != nil {
		return ProxyDelivery{}, err
	}
	return ProxyDelivery{rep: rep}, nil
}

func main() {
	delivery, err := NewProxyDelivery()
	if err != nil {
		log.Error().Err(err)
		return
	}
	r := mux.NewRouter()
	r.Use(SessionMiddleware())
	r.HandleFunc("/", delivery.proxyHandler).Methods(http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodOptions)

	http.ListenAndServe(":8080", r)
}

func WriteToFile(fileName string, data []byte) error {
	file, _ := os.Create(fileName)
	_, err := file.Write(data)
	return err
}

func GetRedirectUrl(r *http.Request) string {
	var redirectedUrl string
	redirectedUrl = r.URL.Query().Get("url")
	if redirectedUrl == "" {
		redirectedUrl = r.RequestURI
	}
	return redirectedUrl
}

func copyRequest(r *http.Request) *http.Request {
	redirectedUrl := GetRedirectUrl(r)
	redirectedRequest, err := http.NewRequest(r.Method, redirectedUrl, r.Body)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil
	}
	delete(r.Header, "Proxy-Connection")
	redirectedRequest.Header = r.Header
	for _, cook := range r.Cookies() {
		redirectedRequest.AddCookie(cook)
	}
	return redirectedRequest
}

func (d ProxyDelivery) proxyHandler(w http.ResponseWriter, r *http.Request) {

	userId := r.Context().Value("ID").(string)
	const timeOut = 5 * time.Second
	client := http.Client{Timeout: timeOut}
	redirectedRequest := copyRequest(r)
	redirectedUrl := redirectedRequest.URL.String()

	resp, err := client.Do(redirectedRequest)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	w.WriteHeader(http.StatusMovedPermanently)
	w.Header().Set("Server", "nginx/1.14.1")
	w.Header().Set("Connection", "close")
	w.Header().Set("Location", redirectedUrl)

	info := ProxyInfo{
		Url:            redirectedUrl,
		HeaderInfo:     headerInfoWithoutCookie(redirectedRequest.Header),
		UserId:         userId,
		Cookies:        resp.Cookies(),
		ResultPage:     body,
		RequestCookies: r.Cookies(),
	}
	err = d.rep.AddProxyInfo(r.Context(), info)
	if err != nil {
		log.Err(err)
	}
	w.Write([]byte("<html>\n<head><title>301 Moved Permanently</title></head>\n<body bgcolor=\"white\">\n<center><h1>301 Moved Permanently</h1></center>\n<hr><center>nginx/1.14.1</center>\n</body>\n</html>\n"))
}

func headerInfoWithoutCookie(header http.Header) http.Header {
	copyMap := http.Header{}
	for key, val := range header {
		if key != "Cookie" {
			copyMap[key] = val
		}
	}
	return copyMap
}
