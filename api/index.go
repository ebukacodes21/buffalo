package api

import (
	"fmt"
	"net/http"
)

func (a *api) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Buffalo</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #000014;
            color: #fff;
        }
        .msg { text-align: center; max-width: 400px; }
        .msg h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; }
        .msg p { font-size: 14px; color: #fff; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="msg">
        <h1>Buffalo Identity Provider</h1>
        <p>Please start the sign-in flow from the application.</p>
    </div>
</body>
</html>`))
	fmt.Printf("info: unauthenticated access to %s from %s\n", r.URL.Path, r.RemoteAddr)
}
