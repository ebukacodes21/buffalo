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
                .msg p { font-size: 14px; color: rgba(255,255,255,0.7); line-height: 1.6; margin-bottom: 28px; }
                .btn {
                    display: inline-block;
                    padding: 11px 22px;
                    border-radius: 6px;
                    font-size: 13px;
                    font-weight: 500;
                    font-family: 'Inter', sans-serif;
                    text-decoration: none;
                    cursor: pointer;
                    transition: background 0.2s, border-color 0.2s;
                    margin: 0 6px;
                }
                .btn-primary-ext { background: #108cf8; color: #fff; border: none; }
                .btn-primary-ext:hover { background: #1267cf; }
                .btn-secondary { background: transparent; color: rgba(255,255,255,0.8); border: 1px solid rgba(255,255,255,0.25); }
                .btn-secondary:hover { border-color: rgba(255,255,255,0.5); color: #fff; }
                .footer {
                    position: fixed; bottom: 24px; left: 0; right: 0;
                    text-align: center;
                    font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase;
                    color: rgba(255,255,255);
                }
                .panel-logo {
                    position: fixed; top: 32px; left: 40px;
                    height: 30px; width: auto; opacity: 0.95;
                }
            </style>
        </head>
        <body>
            <img class="panel-logo" src="/static/arkad-logo-grey.png" alt="Arkad Business Solutions logo">
            <div class="msg">
                <h1>Buffalo Identity Provider</h1>
                <p>Please start the sign-in flow from the application.</p>
                <button type="button" class="btn btn-secondary" id="backBtn" onclick="history.back()">Go back</button>
            </div>
            <div class="footer">
                Secured by Buffalo
            </div>
            <script>
                if (history.length <= 1) {
                    document.getElementById('backBtn').style.display = 'none';
                }
            </script>
        </body>
        </html>`))
	fmt.Printf("info: unauthenticated access to %s from %s\n", r.URL.Path, r.RemoteAddr)
}
