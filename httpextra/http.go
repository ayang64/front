package httpextra

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ResponseRecorder struct {
	Status int
	Bytes  int
	http.ResponseWriter
}

type CommonLog struct {
	W io.Writer
	H http.Handler
}

func (r *ResponseRecorder) Write(b []byte) (int, error) {
	n, e := r.ResponseWriter.Write(b)
	r.Bytes += n
	return n, e
}

func (r *ResponseRecorder) WriteHeader(s int) {
	r.Status = s
	r.ResponseWriter.WriteHeader(s)
}

func (cl CommonLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//
	now := time.Now()
	recorder := ResponseRecorder{ResponseWriter: w}
	cl.H.ServeHTTP(&recorder, r)

	// %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined
	user, _, _ := r.BasicAuth()
	fmt.Fprintln(cl.W,
		strings.Join(
			[]string{
				r.Host,
				func() string { addr, _, _ := strings.Cut(r.RemoteAddr, ":"); return addr }(),
				"-",
				user,
				now.Format("[02/Jan/2006:15:04:05 -0700]"),
				fmt.Sprintf("%q", strings.Join([]string{r.Method, r.URL.Path, r.Proto}, " ")),
				strconv.Itoa(recorder.Status),
				strconv.Itoa(recorder.Bytes),
				fmt.Sprintf("%q", r.URL),
				fmt.Sprintf("%q", r.UserAgent()),
			}, " "))
}
