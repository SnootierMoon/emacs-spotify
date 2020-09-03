;;; spotify+.el --- Control Spotify -*- lexical-binding: t -*-

;; Copyright (C) 2020 Akshay Trivedi

;; Author: Akshay Trivedi <aku24.7x3@gmail.com>
;; Maintainer: Akshay Trivedi <aku24.7x3@gmail.com>
;; Version: 0.0.1
;; Created: 9 Aug 2020
;; Keywords: hypermedia
;; Package-Requires: ((emacs "25.1") (simple-httpd "1.5.1"))
;; Homepage: https://github.com/SnootierMoon/emacs-spotify-plus

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Spotify plugin using the PKCE Oauth2 flow (in early development).
;; See README.org for more information.

;;; Code:

;;;; Requires

(require 'browse-url)
(require 'json)
(require 'map)
(require 'simple-httpd)
(require 'subr-x)
(require 'url)
(require 'widget)
(require 'wid-edit)

;;;; Variables

(defgroup spotify+ nil
  "Spotify Plus."
  :group 'applications)

(defcustom spotify+-log-buffer-name "*Spotify+ Log*"
  "Name for the Spotify+ log buffer."
  :group 'spotify+
  :type 'string)

(defcustom spotify+-client-id "ee9e6d2cdba8448f9fadfbf85678273e"
  "Client ID for for authorization.

The default Client ID is SnootierMoon's Emacs Spotify Plus
application.  To register your own application, go to
<https://developer.spotify.com/dashboard/applications>."
  :group 'spotify+
  :type 'string)

(defcustom spotify+-token-refresher-delay 1800
  "Delay for repeating for `spotify+--token-refresher'."
  :group 'spotify+
  :type 'string)

(defconst spotify+--scopes (list "user-modify-playback-state") ; This is the only scope in use right now.
  ;; '("playlist-modify-private"
  ;;  "playlist-modify-public"
  ;;  "playlist-read-collaborative"
  ;;  "playlist-read-private"
  ;;  "user-follow-modify"
  ;;  "user-follow-read"
  ;;  "user-library-modify"
  ;;  "user-library-read"
  ;;  "user-modify-playback-state"
  ;;  "user-read-currently-playing"
  ;;  "user-read-playback-position"
  ;;  "user-read-playback-state"
  ;;  "user-read-private"
  ;;  "user-read-recently-played"
  ;;  "user-top-read")
  "List of OAuth2 scopes (permissions).")

(define-error 'spotify+--error "Spotify+ error" 'error)
(define-error 'spotify+--no-token-error "Spotify+ token is nil." 'spotify+--error)
(define-error 'spotify+--convert-error "Spotify+ conversion failed." 'spotify+--error)

(defvar spotify+--challenge nil
  "Data relevant to the OAuth2 \"Login with Spotify\" step.

Generated by: `spotify+--challenge-new'.

Contains the code-challenge, code-verifier, redirect-uri,
  scope, and state.")

(defvar spotify+--token nil
  "Alist of data relevant to the access token for API usage.

Generated by: `spotify+--token-new' during login, and
              `spotify+--token-refresh' if a token exists.

Contains the access_token, expires_in, refresh_token, scope,
  and token_type (when authorization succeeds).")

(defvar spotify+--token-refresher nil
  "Timer that calls `spotify+--token-refresh'.

Generated by: `snoot+--token-new' during login.")

(defconst spotify+--endpoint-account       "accounts.spotify.com/")
(defconst spotify+--endpoint-api           "api.spotify.com/v1/")

(defconst spotify+--endpoint-account-auth  (concat spotify+--endpoint-account "authorize/"))
(defconst spotify+--endpoint-account-token (concat spotify+--endpoint-account "api/token/"))

(defconst spotify+--endpoint-api-next      (concat spotify+--endpoint-api "me/player/next/"))
(defconst spotify+--endpoint-api-prev      (concat spotify+--endpoint-api "me/player/prev"))
(defconst spotify+--endpoint-api-play      (concat spotify+--endpoint-api "me/player/play/"))
(defconst spotify+--endpoint-api-pause     (concat spotify+--endpoint-api "me/player/pause/"))

(defconst spotify+--endpoint-api-get-playlist (concat spotify+--endpoint-api "playlists/%s/"))
(defconst spotify+--endpoint-api-get-show     (concat spotify+--endpoint-api "shows/%s/"))
(defconst spotify+--endpoint-api-get-track    (concat spotify+--endpoint-api "tracks/%s/"))

(defconst spotify+--display-functions (list (cons "album"    #'spotify+--display-album)
                                            (cons "artist"   #'spotify+--display-artist)
                                            (cons "episode"  #'spotify+--display-episode)
                                            (cons "playlist" #'spotify+--display-playlist)
                                            (cons "show"     #'spotify+--display-show)
                                            (cons "track"    #'spotify+--display-track)
                                            (cons "user"     #'spotify+--display-user)))

(defvar spotify+-display-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map
                       (make-composed-keymap widget-keymap special-mode-map))
    map))

(define-derived-mode spotify+-display-mode
  special-mode "Spotify+ Display"
  "Display an object in a Spotify+ buffer.")

(defvar-local spotify+--buffer-local-data nil
  "Buffer local variable.

Spotify object associated with the current buffer.")

;;;; Utility Functions

(defun spotify+--random-char (charset)
  "Return a character in CHARSET."
  (let* ((pos  (random (length charset)))
         (sub  (substring charset pos))
         (char (string-to-char sub)))
    char))

(defun spotify+--random-string (charset length)
  "Return a LENGTH size string of characters in CHARSET."
  (let* ((charset-list (make-list length charset))
         (char-list    (mapcar #'spotify+--random-char charset-list))
         (string       (apply #'string char-list)))
    string))

(defun spotify+--sha256 (data)
  "Hash DATA into binary using SHA-256 and return the result."
  (secure-hash 'sha256 data nil nil t))

(defun spotify+--b64-to-string (b64)
  "Convert B64 from base64 to a string and return the result."
  (base64-decode-string b64))

(defun spotify+--string-to-b64 (string)
  "Convert STRING from a string to base64 and return the result."
  (base64-encode-string string))

(defun spotify+--b64-to-b64url (b64)
  "Convert B64 from base64 to base64url and return the result."
  (let* ((b64u   (replace-regexp-in-string "=" "" b64))
         (b64ur  (replace-regexp-in-string "+" "-" b64u))
         (b64url (replace-regexp-in-string "/" "_" b64ur)))
    b64url))

(defun spotify+--b64url-to-b64 (b64url)
  "Convert B64URL from base64url to base64 and return the result."
  (let* ((b64ur (replace-regexp-in-string "_" "/" b64url))
         (b64u  (replace-regexp-in-string "-" "+" b64ur))
         (b64   (concat b64u (make-string (% (- 4 (length b64u)) 4) ?\=))))
    b64))

(defun spotify+--string-to-b64url (string)
  "Convert STRING from a string to base64url and return the result."
  (let* ((b64    (spotify+--string-to-b64 string))
         (b64url (spotify+--b64-to-b64url b64)))
    b64url))

(defun spotify+--b64url-to-string (b64url)
  "Convert B64URL from base64url to a string and return the result."
  (let* ((b64    (spotify+--b64url-to-b64 b64url))
         (string (spotify+--b64-to-string b64)))
    string))

(defun spotify+--log (&rest args)
  "Log ARGS in the Spotify Log buffer."
  (with-current-buffer (get-buffer-create spotify+-log-buffer-name)
    (apply #'insert args)))

(defun spotify+--url-format (url query-params)
  "Format URL and QUERY-PARAMS into a URL and return the URL."
  (concat "https://" url "?" (url-build-query-string query-params)))

(defun spotify+--url-browse (url &optional query-params)
  "Open URL in a browser with QUERY-PARAMS."
  (browse-url (spotify+--url-format url query-params)))

(defun spotify+--url-retrieve (method url callback &optional data headers query-params raw)
  "Convenience wrapper over `url-retrieve'.

Set `url-request-method' to METHOD.
Set `url-request-data' to DATA.
Set `url-request-extra-headers' to HEADERS plus
  Content-Type: application/x-www-form-urlencoded.
Retrieve data from URL with QUERY-PARAMS.
Call CALLBACK when a response is recieved."
  (let ((url-request-method        (alist-get method '((GET . "GET") (POST . "POST") (PUT . "PUT"))))
        (url-request-data          (url-build-query-string data))
        (url-request-extra-headers (append headers '(("Content-Type" . "application/x-www-form-urlencoded")))))
    (url-retrieve (if raw url (spotify+--url-format url query-params))
                  (lambda (_)
                    (goto-char (eval 'url-http-end-of-headers))
                    (funcall callback))
                  nil t)))
;;;; Authorization Functions

(defun spotify+--challenge-new ()
  "Generate an OAuth2 challenge."
  (let* ((code-verifier      (spotify+--random-string "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~" 64))
         (code-challenge     (spotify+--sha256 code-verifier))
         (code-challenge-b64 (spotify+--string-to-b64url code-challenge))
         (redirect-uri       (concat "http://localhost:" (number-to-string httpd-port) "/emacs-spotify-plus-login/"))
         (scope              (mapconcat #'identity spotify+--scopes " "))
         (state              (spotify+--random-string "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 32)))
    (setq spotify+--challenge `((code-challenge . ,code-challenge-b64)
                                (code-verifier  . ,code-verifier)
                                (redirect-uri   . ,redirect-uri)
                                (scope          . ,scope)
                                (state          . ,state)))))

(defun spotify+--login ()
  "Open a \"Login with Spotify\" page."
  (spotify+--challenge-new)
  (map-let (code-challenge redirect-uri scope state) spotify+--challenge
    (spotify+--url-browse
     spotify+--endpoint-account-auth
     `(("client_id"            ,spotify+-client-id)
       ("code_challenge"        ,code-challenge)
       ("code_challenge_method" "S256")
       ("redirect_uri"          ,redirect-uri)
       ("response_type"         "code")
       ("scope"                 ,scope)
       ("state"                 ,state)))))

(defun spotify+--token-refresher-delete ()
  "Delete `spotify+--token-refresh-timer'."
  (when spotify+--token-refresher
    (cancel-timer spotify+--token-refresher)
    (setq spotify+--token-refresher nil)))

(defun spotify+--token-refresher-set ()
  "Set a new `spotify+--token-refresh-timer'."
  (spotify+--token-refresher-delete)
  (setq spotify+--token-refresher
        (run-at-time t spotify+-token-refresher-delay #'spotify+--token-refresh)))

(defun spotify+--token-delete ()
  "Delete `spotify+--token'."
  (setq spotify+--token nil))

(defun spotify+--token-set (token)
  "Set `spotify+--token' to TOKEN if it is valid."
  (if (alist-get 'error token)
      (spotify+--token-full-delete)
    (setq spotify+--token token)))

(defun spotify+--token-full-delete ()
  "Delete `spotify+--token' and `spotify+--token-refresher'."
  (spotify+--token-delete)
  (spotify+--token-refresher-delete))

(defun spotify+--token-full-set (token)
  "Set `spotify+--token' to TOKEN and set a new `spotify+--token-refresher'."
  (spotify+--token-set token)
  (spotify+--token-refresher-set))

(defun spotify+--token-get ()
  "Return the access token as an authorization url header."
  (map-let (access_token) spotify+--token
    (when access_token
      `(("Authorization" . ,(concat "Bearer " access_token))))))

(defun spotify+--token-new (code)
  "Set `spotify+--token' after \"Login with Spotify\" returned CODE.
Also sets a new `spotify+--token-refresher'."
  (map-let (code-verifier redirect-uri) spotify+--challenge
    (spotify+--url-retrieve 'POST
                            spotify+--endpoint-account-token
                            (lambda ()
                              (spotify+--token-set (json-read)))
                            `(("client_id"      ,spotify+-client-id)
                              ("code"           ,code)
                              ("code_verifier"  ,code-verifier)
                              ("grant_type"     "authorization_code")
                              ("redirect_uri"   ,redirect-uri)))))

(defun spotify+--token-refresh ()
  "Refresh `spotify+--token'."
  (map-let (refresh_token) spotify+--token
    (if refresh_token
        (spotify+--url-retrieve 'POST
                                spotify+--endpoint-account-token
                                (lambda ()
                                  (spotify+--token-set (json-read)))
                                `(("client_id"      ,spotify+-client-id)
                                  ("grant_type"     "refresh_token")
                                  ("refresh_token"  ,refresh_token)))
      (spotify+--token-full-delete))))

(defservlet* emacs-spotify-plus-login text/plain (state error code)
  (cond ((not (string= state (alist-get 'state spotify+--challenge)))
         (insert "Invalid state. Try logging in with Spotify again."))
        ((identity error) (insert "Error: " error))
        (t (spotify+--token-new code))))

;;;; Interactive Commands

;;;###autoload
(defun spotify+-start ()
  "Initialize Spotify+."
  (interactive)
  (httpd-start)
  (spotify+--login))

(defun spotify+-stop ()
  "Free all Spotify resources."
  (interactive)
  (spotify+--token-full-delete))

;;;###autoload
(defun spotify+-next ()
  "Go to the next song."
  (interactive)
  (if spotify+--token
      (spotify+--url-retrieve 'POST
                              spotify+--endpoint-api-next
                              (lambda ())
                              nil
                              (spotify+--token-get))
    (signal 'spotify+--no-token-error nil)))

;;;###autoload
(defun spotify+-prev ()
  "Go to the previous song."
  (interactive)
  (if spotify+--token
      (spotify+--url-retrieve 'POST
                              spotify+--endpoint-api-prev
                              (lambda ())
                              nil
                              (spotify+--token-get))
    (signal 'spotify+--no-token-error nil)))

;;;###autoload
(defun spotify+-play ()
  "Play the current song."
  (interactive)
  (if spotify+--token
      (spotify+--url-retrieve 'PUT
                              spotify+--endpoint-api-play
                              (lambda ())
                              nil
                              (spotify+--token-get))
    (signal 'spotify+--no-token-error nil)))

;;;###autoload
(defun spotify+-pause ()
  "Pause the current song."
  (interactive)
  (if spotify+--token
      (spotify+--url-retrieve 'PUT
                              spotify+--endpoint-api-pause
                              (lambda ())
                              nil
                              (spotify+--token-get))
    (signal 'spotify+--no-token-error nil)))

(defun spotify+--display-album ()
  "Display DATA as a Spotify album in a buffer."
  (map-let () spotify+--buffer-local-data
    (widget-insert "yeet")))

(defun spotify+--display-artist ()
  "Display DATA as a Spotify album in a buffer."
  (map-let (followers genres name popularity) spotify+--buffer-local-data
    (widget-insert name "\n")
    (widget-insert "\n")
    (widget-insert "Followers: " (number-to-string (alist-get 'total followers)) "\n")
    (widget-insert "Popularity: " (number-to-string popularity) "%\n")
    (widget-insert "\n")
    (widget-insert "Genres:\n")
    (mapc (lambda (genre) (widget-insert " - " genre "\n")) genres)))

(defun spotify+--display-episode ()
  "Display DATA as a Spotify album in a buffer."
  (map-let () spotify+--buffer-local-data
    (widget-insert "yeet")))

(defun spotify+--display-playlist ()
  "Display DATA as a Spotify album in a buffer."
  (map-let () spotify+--buffer-local-data
    (widget-insert "yeet")))

(defun spotify+--display-show ()
  "Display DATA as a Spotify album in a buffer."
  (map-let () spotify+--buffer-local-data
    (widget-insert "yeet")))

(defun spotify+--display-track ()
  "Display DATA as a Spotify album in a buffer."
  (map-let () spotify+--buffer-local-data
    (widget-insert "yeet")))

(defun spotify+--display-user ()
  "Display DATA as a Spotify album in a buffer."
  (map-let () spotify+--buffer-local-data
    (widget-insert "yeet")))

(defun spotify+--display-data (data)
  "Display DATA as a Spotify object in a buffer."
  (map-let (type uri) data
    (switch-to-buffer (concat "*" uri "*"))
    (let ((inhibit-read-only t))
      (erase-buffer))
    (remove-overlays)
    (kill-all-local-variables)
    (spotify+-display-mode)
    (setq spotify+--buffer-local-data data)
    (funcall (alist-get type spotify+--display-functions nil nil #'string=))
    (widget-setup)
    (goto-char (point-min))))

(defun spotify+--display-href (href)
  "Display the json data retrieved from HREF in a buffer."
  (if spotify+--token
      (spotify+--url-retrieve 'GET
                              href
                              (lambda ()
                                (spotify+--display-data (json-read)))
                              nil
                              (spotify+--token-get)
                              nil t)
    (signal 'spotify+--no-token-error nil)))

(provide 'spotify+)
;;; spotify+.el ends here
