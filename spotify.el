;;; spotify.el --- Control Spotify from within Emacs -*- lexical-binding: t -*-

;; Copyright (C) 2020-2023 Akshay Trivedi

;; Author: Akshay Trivedi <aku24.7x3@gmail.com>
;; Maintainer: Akshay Trivedi <aku24.7x3@gmail.com>
;; Version: 0.0.2
;; Created: 9 Aug 2020
;; Keywords: hypermedia
;; Package-Requires: ((emacs "29.1"))
;; Homepage: https://github.com/SnootierMoon/emacs-spotify

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

;;;; Small package for controlling Spotify interactively from within Emacs
;;;; using the Spotify Web API.

;;; Code:

(eval-when-compile
  (require 'map))

;;;; Constants

(defconst spotify--client-id "ee9e6d2cdba8448f9fadfbf85678273e"
  "The Client ID for the Emacs Spotify SDA.

For more information, see:
`https://developer.spotify.com/documentation/web-api/concepts/apps'.")

(defconst spotify--endpoint-auth "accounts.spotify.com/authorize"
  "Spotify API endpoint: authorization.

For more information, see:
`https://developer.spotify.com/documentation/web-api/concepts/authorization'.")

(defconst spotify--endpoint-access-token "accounts.spotify.com/api/token"
  "Spotify API endpoint: access token.

For more information, see:
`https://developer.spotify.com/documentation/web-api/concepts/access-token'.")

(defconst spotify--endpoint-next "api.spotify.com/v1/me/player/next"
  "Spotify API endpoint: skip to next.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/skip-users-playback-to-next-track'.")

(defconst spotify--endpoint-prev "api.spotify.com/v1/me/player/previous"
  "Spotify API endpoint: skip to previous.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/skip-users-playback-to-previous-track'.")

(defconst spotify--endpoint-play "api.spotify.com/v1/me/player/play"
  "Spotify API endpoint: pause playback.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/start-a-users-playback'.")

(defconst spotify--endpoint-pause "api.spotify.com/v1/me/player/pause"
  "Spotify API endpoint: start/resume playback.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/pause-a-users-playback'.")

(defconst spotify--scopes '("user-modify-playback-state")
  "The set of permissions that Emacs Spotify requires.

For more information, see:
`https://developer.spotify.com/documentation/web-api/concepts/scopes'.")

(define-error 'spotify--error
              "Spotify"
              'error)

(define-error 'spotify--api-error
              "Spotify API"
              'spotify--error)

;;;; Global State Variables

(defvar spotify--auth-status 'uninitialized
  "Enum representing the authorization status.

 - uninitialized: The user has not started the Emacs Spotify
     authorization process yet.
 - authorizing: The user has been prompted to login, awaiting a
   response.
 - authorized: The user has authorized the Emacs Spotify package.")

(defvar spotify--auth-challenge nil
  "Oauth2 PKCE challenge generated during auth.

Represented as an alist:
  ((code-verifier . The generated code verifier)
   (code-challenge . The base64 encode code challenge)n
   (redirect-uri . Redirect URI for retreiving the access token)
   (state . Randomly generated string))

For more information, see:
`https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow'.")

(defvar spotify--auth-redirect-proc nil
  "Mini HTTP server to handle redirects from the \"Login with Spotify\" page.")

(defvar spotify--access-token nil
  "Token that allows the application to make API requests.

For more information, see:
`https://developer.spotify.com/documentation/web-api/concepts/access-token'.")

(defvar spotify--refresh-token nil
  "Token that allows the application to refresh `spotify--access-token'.

For more information, see:
 `https://developer.spotify.com/documentation/web-api/tutorials/refreshing-tokens'.")

(defvar spotify--token-refresher nil
  "The timer that refreshes `spotify--access-token' and `spotify--refresh-token'.

Runs on a periodic interval determined by `spotify-token-refresher-interval'.")

;;;; Customization Variables

(defgroup spotify nil
  "Options for configuring Emacs Spotify."
  :group 'applications)

(defcustom spotify-keymap-prefix "M-s"
  "The prefix key for all Emacs Spotify key bindings.

Set to nil to disable the default Emacs Spotify keymaps."
  :type 'key
  :group 'spotify)

(defgroup spotify-log nil
  "Options for configuring the Emacs Spotify logging system."
  :group 'spotify)

(defcustom spotify-enable-logging nil
  "Non-nil if debug messages should be logged."
  :type 'boolean
  :group 'spotify-log)

(defcustom spotify-log-buffer-name "*Spotify Log*"
  "The name of the buffer into which debug messages should be logged."
  :type 'string
  :group 'spotify-log)

(defcustom spotify-log-prefix "[%r] "
  "The prefix of the debug messages.

This string should be compatible with `format-time-string'."
  :type 'string
  :group 'spotify-log)

(defcustom spotify-token-refresher-interval 3000
  "How often `spotify--token-refresher' should repeat, in seconds."
  :type 'natnum
  :group 'spotify)

(defcustom spotify-auth-redirect-port 8080
  "How often `spotify--token-refresher' should repeat, in seconds.

Due to how the application is configured in the Spotify dashboard,
only a handful of ports will actually work.  If you want to choose a
different port, please contact me by submitting an issue on GitHub,
since it is pretty easy for me to add other alternative ports."
  :type '(choice (const 80)
                 (const 8000)
                 (const 8080)
                 (const 8888)
                 (const 42069))
  :group 'spotify)

;;;; Minor Mode

(defvar spotify--keymap
  (let ((map (make-keymap)))
    (keymap-set map "g" #'spotify-play)
    (keymap-set map "G" #'spotify-pause)
    (keymap-set map "f" #'spotify-next)
    (keymap-set map "n" #'spotify-next)
    (keymap-set map "b" #'spotify-prev)
    (keymap-set map "p" #'spotify-prev)
    map)
  "Emacs Spotify keymap.

Gets bound to `spotify-keymap-prefix' when `spotify-mode' is
enabled.")

(defun spotify--generate-mode-map ()
  "Create the `spotify-mode-map' based on the user's preferences."
  (let ((map (make-sparse-keymap)))
    (when spotify-keymap-prefix
      (keymap-set map
                  spotify-keymap-prefix
                  spotify--keymap)
      map)))

(define-minor-mode spotify-mode
  "Toggle the Emacs Spotify minor mode.

Enable the key bindings in `spotify--keymap'."
  :global t
  :keymap (spotify--generate-mode-map)
  :interactive nil
  :group 'spotify
  (when spotify-mode
    (spotify--refresh-mode-map)))

(defun spotify--refresh-mode-map ()
  "Update the value of `spotify-mode-map' based on the user's preferences."
  (setq spotify-mode-map (spotify--generate-mode-map))
  (when-let ((it (assq 'spotify-mode minor-mode-map-alist)))
    (setcdr it spotify-mode-map)))

;;;; Utility Functions

(defun spotify--random-char (charset)
  "Return a character from CHARSET."
  (elt charset (random (length charset))))

(defun spotify--random-string (charset length)
  "Return a string of characters from CHARSET with the given LENGTH."
  (apply #'string (mapcar #'spotify--random-char
                          (make-list length charset))))

(defun spotify--log (message &rest args)
  "Log a message into the buffer called `spotify-log-buffer-name'.

The parameters MESSAGE and ARGS are formatted with `format'.
The value of `spotify-log-prefix' is formatted with
`format-time-string' and prepended to the message.

If `spotify-enable-logging' is nil, nothing happens."
  (when spotify-enable-logging
    (with-current-buffer (get-buffer-create spotify-log-buffer-name)
      (goto-char (point-max))
      (insert
       (format-time-string spotify-log-prefix)
       (apply #'format message args)
       "\n"))))

(defun spotify--format-url (endpoint &optional query-string)
  "Build a full URL given an ENDPOINT and a QUERY-STRING.

The outputted url will use the HTTPS scheme.

The QUERY-STRING parameter should be compatible with
`url-build-query-string'."
  (if query-string
      (format "https://%s?%s" endpoint (url-build-query-string
                                        query-string))
    (concat "https://" endpoint)))

(defun spotify--browse-url (endpoint &optional query-string)
  "Wrapper around `browse-url'.

The parameters ENDPOINT and QUERY-STRING are formatted with
`spotify--format-url'."
  (let ((full-url (spotify--format-url endpoint query-string)))
    (spotify--log "Opening \"%s\" in the browser..." full-url)
    (browse-url full-url)))

(defun spotify--parse-http-content ()
  "Parse the HTTP content in the current buffer.

The current buffer should have been generated by `url-retrieve' or
`url-retrieve-synchronously'."
  (let* ((content (buffer-substring (1+ (eval 'url-http-end-of-headers))
                                    (point-max))))
    (cond  ((not (eval 'url-http-content-type))
            nil)
           ((string-match-p "^\\s *application/json\\s *\\(;.*\\)?$"
                            (eval 'url-http-content-type))
            (json-parse-string content))
           (t
            content))))


(defun spotify--retrieve-url (endpoint callback &rest args)
  "Wrapper around `url-retrieve'.
  
Send an HTTP request to ENDPOINT.
Call CALLBACK with the content of the response when it's received.
ARGS is a plist that can have :method, :data, :headers, and :params.
 - :method is `url-request-method'.
 - :data is `url-request-data'.
 - :headers is `url-request-extra-headers'
     (automatically adds \"Content-Type: application/x-www-form-urlencoded\")
 - :params are the query-parameters."
  (let ((full-url                  (spotify--format-url endpoint (plist-get args :params)))
        (url-request-method        (plist-get args :method))
        (url-request-data          (url-build-query-string (plist-get args :data)))
        (url-request-extra-headers (plist-get args :headers)))
    (push '("Content-Type" . "application/x-www-form-urlencoded") url-request-extra-headers)
    (spotify--log
     "Sending request to \"%s\"...\n - METHOD: %s\n - DATA: %s\n - HEADERS: %s\n - URL: %s"
     endpoint
     url-request-method
     url-request-data
     url-request-extra-headers
     full-url)
    (url-retrieve full-url
                  (lambda (status)
                    (let ((data (spotify--parse-http-content)))
                      (spotify--log "Received response from \"%s\"!\n - Data %s" endpoint data)
                      (funcall callback status data))))))

(defun spotify--retrieve-url-synchronously (endpoint &rest args)
  "Wrapper around `url-retrieve-synchronously'.
  
Send an HTTP request to ENDPOINT.
Return the content of the response when it's received.
ARGS is a plist that can have :method, :data, :headers, and :params.
 - :method is `url-request-method'.
 - :data is `url-request-data'.
 - :headers is `url-request-extra-headers'
     (automatically adds \"Content-Type: application/x-www-form-urlencoded\")
 - :params are the query-parameters."
  (let ((full-url                  (spotify--format-url endpoint (plist-get args :params)))
        (url-request-method        (plist-get args :method))
        (url-request-data          (url-build-query-string (plist-get args :data)))
        (url-request-extra-headers (plist-get args :headers)))
    (push '("Content-Type" . "application/x-www-form-urlencoded") url-request-extra-headers)
    (spotify--log
     "Sending request to \"%s\"...\n - METHOD: %s\n - DATA: %s\n - HEADERS: %s\n - URL: %s"
     endpoint
     url-request-method
     url-request-data
     url-request-extra-headers
     full-url)
    (with-current-buffer (url-retrieve-synchronously full-url nil t)
      (let ((data (spotify--parse-http-content)))
        (spotify--log "Received response from \"%s\"!\n - Data %s" endpoint data)
        data))))

(defun spotify--token-headers ()
  "Create headers necessary to perform an API request with an access token."
  (if spotify--access-token
      `(("Authorization" . ,(concat "Bearer " spotify--access-token)))
    (signal 'spotify--error '("token is nil, run `spotify-start' first"))))

;;;; Authorization Functions

(defun spotify--generate-challenge ()
  "Generate a new PKCE challenge and store it in `spotify--challenge'.

See the docs for `spotify--challenge' for more info."
  (random t)
  (let* ((code-verifier (spotify--random-string
                         "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
                         64))
         (code-challenge (secure-hash 'sha256 code-verifier nil nil t))
         (code-challenge-b64 (base64url-encode-string code-challenge t))
         (redirect-uri (format "http://localhost:%d/" spotify-auth-redirect-port))
         (state (spotify--random-string
                 "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                 32)))
    (spotify--log "Creating a new PKCE challenge \"%s\"..." code-challenge-b64)
    (setq spotify--auth-challenge `((code-verifier . ,code-verifier)
                                    (code-challenge . ,code-challenge-b64)
                                    (redirect-uri . ,redirect-uri)
                                    (state . ,state)))))

(defun spotify--login ()
  "Open a \"Login with Spotify\" page in the browser."
  (map-let (code-challenge redirect-uri state) spotify--auth-challenge
    (spotify--browse-url spotify--endpoint-auth
                         `(("client_id"             ,spotify--client-id)
                           ("code_challenge"        ,code-challenge)
                           ("code_challenge_method" "S256")
                           ("redirect_uri"          ,redirect-uri)
                           ("response_type"         "code")
                           ("scope"                 ,(string-join spotify--scopes " "))
                           ("state"                 ,state)))))

(defun spotify--auth-redirect-filter (proc data)
  "Process filter for network connections of `spotify--auth-redirect-proc'.

Called when PROC receives new DATA."
  (with-current-buffer (or (process-buffer proc)
                           (set-process-buffer proc
                                               (get-buffer-create
                                                (format " %s " (process-name proc)))))
    (goto-char (point-max))
    (insert data)
    (when (> (line-number-at-pos) 1)
      (goto-char (point-min))
      (when (looking-at "^GET \\/\\?\\(.+\\) HTTP\\/1.1$")
        (let* ((params (url-parse-query-string (match-string 1)))
               (body
                (map-let (code ('error err) state) (mapcar (lambda (p) (cons (intern (car p)) (cadr p))) params)
                  (cond ((not (string= state (alist-get 'state spotify--auth-challenge)))
                         (format "<p>Error: State mismatch \"%s\" \"%s\"</p>"
                                 state
                                 (alist-get 'state spotify--auth-challenge)))
                        (err
                         (format "<p>Error: %s</p>" err))
                        (code
                         (spotify--request-access-token code)
                         "<p>Success! You may now return to Emacs. Check the logs if you have any issues.</p>")
                        (t
                         "<p>Error: no code in response.</p>"))))
               (content
                (format "<html><head><title>Emacs Spotify</title></head><body>%s</body></html>" body)))
          (process-send-string
           proc
           (format
            "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n%s"
            (length content) content))))
      (process-send-eof)
      (delete-process)
      (kill-buffer))))

(defun spotify--auth-redirect-sentinel (proc event)
  "Process sentinel for network connections of `spotify--auth-redirect-proc'.

Called when PROC signals a new EVENT."
  (when (and (string= event "closed") (process-buffer proc))
    (kill-buffer (process-buffer proc))))


(defun spotify--init-auth-redirect-proc ()
  "Initialize `spotify--auth-redirect-proc'."
  (spotify--delete-auth-redirect-proc)
  (setq spotify--auth-redirect-proc
        (make-network-process
         :name "Spotify Redirect Handler"
         :host 'local
         :service spotify-auth-redirect-port
         :family 'ipv4
         :filter #'spotify--auth-redirect-filter
         :sentinel #'spotify--auth-redirect-sentinel
         :server 2
         :noquery t)))

(defun spotify--delete-auth-redirect-proc ()
  "Delete `spotify--auth-redirect-proc' if it exists."
  (when (process-live-p spotify--auth-redirect-proc)
    (delete-process spotify--auth-redirect-proc))
  (setq spotify--auth-redirect-proc nil))

(defun spotify--set-token (data)
  "Set the access/refresh token given DATA.

DATA is the parsed json response received from requesting an access
token from `spotify--endpoint-access-token'.  This function can be
called for both the initial access token and for refreshing the access
token with a refresh token because both use the same response format."
  (map-let (("access_token" access-token)
            ("expires_in" expires-in)
            ("refresh_token" refresh-token)) data
    (when (>= spotify-token-refresher-interval expires-in)
      (spotify--log "Warning: `spotify-token-refresher-interval' is %d, but token expires in %d"
                    spotify-token-refresher-interval
                    expires-in))
    (setq spotify--access-token access-token)
    (setq spotify--refresh-token refresh-token)))

(defun spotify--request-access-token (code)
  "Request an initial access and refresh token using CODE.

CODE is received after the user grants the application authorization:
The code is acquired by listening for a redirect from the \"Login with
Spotify\" page.

For more information, see:
`https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow\#request-user-authorization'."
  (map-let (code-verifier redirect-uri) spotify--auth-challenge
    (spotify--retrieve-url spotify--endpoint-access-token
                           (lambda (_ data)
                             (if-let ((err (gethash "error" data)))
                                 (spotify--log "Request access token error %s"
                                               (gethash "error_description" data))
                               (setq spotify--auth-status 'authorized)
                               (spotify--delete-auth-redirect-proc)
                               (spotify--set-token data)
                               (spotify--init-token-refresher)))
                           :method "POST"
                           :data `(("grant_type"    "authorization_code")
                                   ("code"          ,code)
                                   ("redirect_uri"  ,redirect-uri)
                                   ("client_id"     ,spotify--client-id)
                                   ("code_verifier" ,code-verifier)))))

(defun spotify--refresh-access-token ()
  "Retrieve a new access/refresh token using `spotify--refresh-token'."
  (spotify--log "Running token refresher")
  (when spotify--refresh-token
    (spotify--retrieve-url spotify--endpoint-access-token
                           (lambda (_ data)
                             (if-let ((err (gethash "error" data)))
                                 (spotify--log "Request access token error %s"
                                               (gethash "error_description" data))
                               (spotify--set-token data)))
                           :method "POST"
                           :data `(("client_id"     ,spotify--client-id)
                                   ("grant_type"    "refresh_token")
                                   ("refresh_token" ,spotify--refresh-token)))))

(defun spotify--init-token-refresher ()
  "Initialize `spotify--token-refresher'."
  (spotify--delete-token-refresher)
  (setq spotify--token-refresher
        (run-at-time spotify-token-refresher-interval
                     spotify-token-refresher-interval
                     #'spotify--refresh-access-token)))

(defun spotify--delete-token-refresher ()
  "Delete `spotify--token-refresher' if it exists."
  (when spotify--token-refresher
    (cancel-timer spotify--token-refresher)
    (setq spotify--token-refresher nil)))

(defun spotify--error-check (data)
  "Assert that the json response in DATA does not contain an error."
  (when-let ((data)
             (err (gethash "error" data))
             (message (gethash "message" err)))
    (signal 'spotify--api-error (list message))))

;;;; Interactive Commands

;;;###autoload
(defun start-spotify ()
  "Start Emacs Spotify."
  (interactive)
  (if (eq spotify--auth-status 'authorized)
      (signal 'spotify--error '("already running, run `spotify-restart' to reload"))
    (when (eq spotify--auth-status 'uninitialized)
      (setq spotify--auth-status 'authorizing)
      (spotify--generate-challenge)
      (spotify--init-auth-redirect-proc))
    (spotify--login))
  (spotify-mode 1))

;;;###autoload
(defun stop-spotify ()
  "Stop Emacs Spotify."
  (interactive)
  (spotify--delete-token-refresher)
  (setq spotify--refresh-token nil)
  (setq spotify--access-token nil)
  (spotify--delete-auth-redirect-proc)
  (setq spotify--auth-challenge nil)
  (setq spotify--auth-status 'uninitialized)
  (spotify-mode -1))

;;;###autoload
(defun restart-spotify ()
  "Restart Emacs Spotify."
  (interactive)
  (stop-spotify)
  (start-spotify))

;;;###autoload
(defun spotify-next ()
  "Skip to next track in the user's queue."
  (interactive)
  (let ((data (spotify--retrieve-url-synchronously
               spotify--endpoint-next
               :method "POST"
               :headers (spotify--token-headers))))
    (spotify--error-check data)))

;;;###autoload
(defun spotify-prev ()
  "Skips to previous track in the user’s queue.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/skip-users-playback-to-next-track'."
  (interactive)
  (let ((data (spotify--retrieve-url-synchronously
               spotify--endpoint-prev
               :method "POST"
               :headers (spotify--token-headers))))
    (spotify--error-check data)))

;;;###autoload
(defun spotify-play ()
  "Play the current song in the player."
  (interactive)
  (let ((data (spotify--retrieve-url-synchronously
               spotify--endpoint-play
               :method "PUT"
               :headers (spotify--token-headers))))
    (spotify--error-check data)))

;;;###autoload
(defun spotify-pause ()
  "Pause the current song in the player."
  (interactive)
  (let ((data (spotify--retrieve-url-synchronously
               spotify--endpoint-pause
               :method "PUT"
               :headers (spotify--token-headers))))
    (spotify--error-check data)))

(provide 'spotify)

;;; spotify.el ends here
