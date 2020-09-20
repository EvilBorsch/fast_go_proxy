package main

import (
	"net/http"
)

type ProxyInfo struct {
	UserId             string
	Url                string
	HeaderInfo         http.Header
	ResponseCookies    []*http.Cookie
	ResponseBody       []byte
	RequestCookies     []*http.Cookie
	Method             string
	RequestBody        []byte
	ResponseContentLen int
}
