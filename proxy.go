package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
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

func LoggingMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			log.Info().Msgf(req.RequestURI)

			next.ServeHTTP(w, req)
		})
	}
}

const timeOut = 5 * time.Second

type ProxyDelivery struct {
	rep    Repository
	client http.Client
}

func NewProxyDelivery() (ProxyDelivery, error) {
	rep, err := NewRepository()

	if err != nil {
		return ProxyDelivery{}, err
	}

	return ProxyDelivery{rep: rep, client: http.Client{Timeout: timeOut}}, nil
}

func main() {
	delivery, err := NewProxyDelivery()
	if err != nil {
		log.Error().Err(err)
		return
	}
	r := mux.NewRouter()
	r.Use(SessionMiddleware())
	r.Use(LoggingMiddleware())
	r.HandleFunc("/", delivery.proxyHandler).Methods(http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodOptions)
	r.HandleFunc("/last", delivery.CompleteLastRequest).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/check", delivery.CheckLastRequest).Methods(http.MethodGet, http.MethodPost)

	log.Err(http.ListenAndServe(":8080", r))
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
	redirectedUrl = strings.ReplaceAll(redirectedUrl, "%", "")
	return redirectedUrl
}
func getRequestFromProxyInfo(info ProxyInfo) (*http.Request, error) {
	request, err := http.NewRequest(info.Method, info.Url, bytes.NewReader(info.RequestBody))
	if err != nil {
		return nil, err
	}
	request.Header = info.HeaderInfo
	for _, cook := range info.ResponseCookies {
		request.AddCookie(cook)
	}
	return request, nil

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

func getProxyInfo(r *http.Request, resp *http.Response, userId string) (ProxyInfo, error) {
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return ProxyInfo{}, err
	}
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ProxyInfo{}, err
	}

	info := ProxyInfo{
		Url:                r.URL.String(),
		HeaderInfo:         headerInfoWithoutCookie(r.Header),
		UserId:             userId,
		ResponseCookies:    resp.Cookies(),
		ResponseBody:       responseBody,
		ResponseContentLen: len(responseBody),
		RequestCookies:     r.Cookies(),
		Method:             r.Method,
		RequestBody:        requestBody,
	}
	return info, nil
}

func (d ProxyDelivery) CompleteLastRequest(w http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value("ID").(string)
	proxyInfo, err := d.rep.GetLastProxyInfo(r.Context(), userId)
	if err != nil {
		log.Err(err)
		return
	}
	request, err := getRequestFromProxyInfo(proxyInfo)
	if err != nil {
		log.Err(err)
		return
	}
	resp, err := d.client.Do(request)
	if err != nil {
		log.Err(err)
		return
	}
	info, err := getProxyInfo(r, resp, userId)
	if err != nil {
		log.Err(err)
		return
	}
	w.Write(info.ResponseBody)

}

func (d ProxyDelivery) proxyHandler(w http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value("ID").(string)
	redirectedRequest := copyRequest(r)
	redirectedUrl := redirectedRequest.URL.String()

	resp, err := d.client.Do(redirectedRequest)
	if err != nil {
		log.Error().Msg(err.Error())
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(http.StatusMovedPermanently)
	w.Header().Set("Server", "nginx/1.14.1")
	w.Header().Set("Connection", "close")
	w.Header().Set("Location", redirectedUrl)

	info, err := getProxyInfo(redirectedRequest, resp, userId)
	if err != nil {
		log.Err(err)
	}
	err = d.rep.AddProxyInfo(r.Context(), info)
	if err != nil {
		log.Err(err)
	}
	w.Write([]byte("<html>\n<head><title>301 Moved Permanently</title></head>\n<body bgcolor=\"white\">\n<center><h1>301 Moved Permanently</h1></center>\n<hr><center>nginx/1.14.1</center>\n</body>\n</html>\n"))
}

func (d ProxyDelivery) CheckLastRequest(writer http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value("ID").(string)
	proxyInfo, err := d.rep.GetLastProxyInfo(r.Context(), userId)
	if err != nil {
		log.Err(err)
		return
	}
	lastRequestUrl := proxyInfo.Url

	proxyInfo.Url = getSqlInjectionUrl(lastRequestUrl, "'")
	request1, err := getRequestFromProxyInfo(proxyInfo)
	if err != nil {
		log.Err(err)
		return
	}

	proxyInfo.Url = getSqlInjectionUrl(lastRequestUrl, "\"")
	request2, err := getRequestFromProxyInfo(proxyInfo)
	if err != nil {
		log.Err(err)
		return
	}
	proxyInfo.Url = lastRequestUrl

	differenceCofficient1, err := d.compareRequestAndProxyInfoResults(request1, proxyInfo, userId)
	if err != nil {
		log.Err(err)
		return
	}
	differenceCofficient2, err := d.compareRequestAndProxyInfoResults(request2, proxyInfo, userId)
	if err != nil {
		log.Err(err)
		return
	}

	if differenceCofficient1 < 0.8 || differenceCofficient2 < 0.8 {
		writer.Write([]byte(fmt.Sprintf("Have sql injection in %s", lastRequestUrl)))
		return
	}

	writer.Write([]byte(fmt.Sprintf("No sql injection in %s", lastRequestUrl)))

}

func (d ProxyDelivery) compareRequestAndProxyInfoResults(request *http.Request, info ProxyInfo, userId string) (float32, error) {
	resp, err := d.client.Do(request)
	if err != nil {
		return -1, err
	}
	proxyInfoWithSqlInjectionTry, err := getProxyInfo(request, resp, userId)
	if err != nil {
		return -1, err
	}

	if info.ResponseContentLen < proxyInfoWithSqlInjectionTry.ResponseContentLen {
		return float32(info.ResponseContentLen) / float32(proxyInfoWithSqlInjectionTry.ResponseContentLen), nil
	}
	return float32(proxyInfoWithSqlInjectionTry.ResponseContentLen) / float32(info.ResponseContentLen), nil
}

func getSqlInjectionUrl(ur string, injectionSymbol string) string {
	u, _ := url.Parse(ur)

	values, _ := url.ParseQuery(u.RawQuery)
	for key, val := range values {
		values.Set(key, injectionSymbol+val[0])
	}
	u.RawQuery = values.Encode()
	return u.String()
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
