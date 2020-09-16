package main

import (
	"net/http"
)

type ProxyInfo struct {
	UserId         string
	Url            string
	HeaderInfo     http.Header
	Cookies        []*http.Cookie
	ResultPage     []byte
	RequestCookies []*http.Cookie
}
