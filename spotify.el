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

;;;; Requires

(require 'map)
(require 'url-util)

;;;; Customization Variables

(defgroup spotify nil
  "Options for configuring Emacs Spotify."
  :group 'applications)

(defgroup spotify-log nil
  "Options for configuring the Emacs Spotify logging system."
  :group 'spotify)

(defcustom spotify-enable-logging t
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

(defgroup spotify-auth nil
  "Options for configuring Emacs Spotify authorization."
  :group 'spotify)

(defcustom spotify-token-refresher-interval 3000
  "How often `spotify--token-refresher' should repeat, in seconds."
  :type 'natnum
  :group 'spotify-auth)

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
  :group 'spotify-auth)

(defcustom spotify-close-page-on-auth-redirect t
  "Whether the browser page should close after logging in with Spotify.

May not work on some browsers."
  :type 'boolean
  :group 'spotify-auth)

(defcustom spotify-focus-on-auth-redirect t
  "Whether Emacs should re-take focus after logging in with Spotify."
  :type 'boolean
  :group 'spotify-auth)

;;;; Constants

(defconst spotify--client-id "ee9e6d2cdba8448f9fadfbf85678273e"
  "The Client ID for the Emacs Spotify SDA.

For more information, see:
`https://developer.spotify.com/documentation/web-api/concepts/apps'.")

(defconst spotify--endpoint-auth "accounts.spotify.com/authorize"
  "Spotify API endpoint: authorization.

For more information, see:
`https://developer.spotify.com/documentation/web-api/concepts/authorization'.")

(defconst spotify--endpoint-token "accounts.spotify.com/api/token"
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

;;;; Global Variables

(defvar spotify--auth-status 'unauthorized
  "Enum representing the authorization status.

 - authorized: The user has not started the Emacs Spotify
   authorization process yet.
 - authorizing: The user has been prompted to login, awaiting a
   response.
 - authorized: The user has authorized the Emacs Spotify package.")

(defvar spotify--auth-challenge nil
  "Oauth2 PKCE challenge generated during auth.

Represented as an alist:
  ((code-verifier  . randomly generated string)
   (code-challenge . [A-Za-z_-]+  (base64 encoded code-verifier))
   (redirect-uri   . http://localhost:[port]/)
   (state          . randomly generated string))

For more information, see:
`https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow'.")

(defvar spotify--auth-redirect-process nil
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
  "Build a fully formatted URL given an ENDPOINT and a QUERY-STRING.

The formatted URL uses the HTTPS scheme.

The QUERY-STRING parameter should be compatible with
`url-build-query-string'."
  (if query-string
      (concat "https://" endpoint "?" (url-build-query-string
                                       query-string))
    (concat "https://" endpoint)))

(defun spotify--browse-url (endpoint &optional query-string)
  "Wrapper around `browse-url'.

The parameters ENDPOINT and QUERY-STRING are formatted with
`spotify--format-url'."
  (let ((full-url (spotify--format-url endpoint query-string)))
    (browse-url full-url)))

(defun spotify--parse-http-content ()
  "Parse the content of the HTTP response in the current buffer.

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
 - :params are the query parameters, should be compatible with
   `url-build-query-string'."
  (let ((full-url                  (spotify--format-url endpoint (plist-get args :params)))
        (url-request-method        (plist-get args :method))
        (url-request-data          (url-build-query-string (plist-get args :data)))
        (url-request-extra-headers (cons '("Content-Type" . "application/x-www-form-urlencoded")
                                         (plist-get args :headers))))
    (spotify--log "Sending HTTP request to \"%s\"...\n - url: %s\n - method: %s\n - data: %s\n - headers: %s\n"
                  endpoint
                  full-url
                  url-request-method
                  url-request-data
                  url-request-extra-headers)
    (url-retrieve full-url
                  (lambda (status)
                    (let ((data (spotify--parse-http-content)))
                      (spotify--log "Retrieved HTTP response from \"%s\"\n%s\n"
                                    endpoint
                                    data)
                      (funcall callback status data)))
                  nil t t)))

(defun spotify--retrieve-url-synchronously (endpoint &rest args)
  "Wrapper around `url-retrieve-synchronously'.
  
Send an HTTP request to ENDPOINT.
Return the content of the response when it's received.
ARGS is a plist that can have :method, :data, :headers, and :params.
 - :method is `url-request-method'.
 - :data is `url-request-data'.
 - :headers is `url-request-extra-headers'
   (automatically adds \"Content-Type: application/x-www-form-urlencoded\")
 - :params are the query parameters, should be compatible with
   `url-build-query-string'."
  (let ((full-url                  (spotify--format-url endpoint (plist-get args :params)))
        (url-request-method        (plist-get args :method))
        (url-request-data          (url-build-query-string (plist-get args :data)))
        (url-request-extra-headers (cons '("Content-Type" . "application/x-www-form-urlencoded")
                                         (plist-get args :headers))))
    (spotify--log "Sending HTTP request to \"%s\"...\n - url: %s\n - method: %s\n%s\n - headers: %s\n"
                  endpoint
                  full-url
                  url-request-method
                  url-request-data
                  url-request-extra-headers)
    (with-current-buffer (url-retrieve-synchronously full-url t t)
      (let ((data (spotify--parse-http-content)))
        (spotify--log "Retrieved HTTP response from \"%s\"\n%s\n"
                      endpoint
                      data)
        data))))

(defun spotify--token-headers ()
  "Create the headers necessary to perform an API request with an access token."
  (if spotify--access-token
      `(("Authorization" . ,(concat "Bearer " spotify--access-token)))
    (signal 'spotify--error '("token is nil, run `spotify-start' first"))))

;;;; Authorization Functions

(defun spotify--login ()
  "Open a \"Login with Spotify\" page in the browser.

In addition, generate a new PKCE challenge and store it into
`spotify--auth-challenge' to begin the auth process."
  (random t)
  (let* ((code-verifier (spotify--random-string
                         "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
                         64))
         (code-challenge (base64url-encode-string (secure-hash 'sha256 code-verifier nil nil t) t))
         (redirect-uri (format "http://localhost:%d/" spotify-auth-redirect-port))
         (state (spotify--random-string
                 "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                 32)))
    (setq spotify--auth-challenge `((code-verifier  . ,code-verifier)
                                    (code-challenge . ,code-challenge)
                                    (redirect-uri   . ,redirect-uri)
                                    (state          . ,state)))
    (spotify--browse-url spotify--endpoint-auth
                         `(("client_id"             ,spotify--client-id)
                           ("response_type"         "code")
                           ("redirect_uri"          ,redirect-uri)
                           ("state"                 ,state)
                           ("scope"                 ,(string-join spotify--scopes " "))
                           ("code_challenge_method" "S256")
                           ("code_challenge"        ,code-challenge)))))

(defun spotify--auth-redirect-buffer (process)
  "Buffer for a network connection PROCESS of `spotify--auth-redirect-process'."
  (or (process-buffer process)
      (set-process-buffer
       process
       (get-buffer-create (concat " *" (process-name process) "* ")))))

(defun spotify--handle-redirect-and-serve-html (redirect-data)
  (let (body (head ""))
    (map-let (state) spotify--auth-challenge
      (map-let (("code" code) ("error" err) ("state" in-state)) redirect-data
        (cond ((not (string= state (car in-state)))
               (setq body (format "<h1>Error</h1><p>State mismatch: \"%s\" vs. \"%s\"</p>"
                                       state
                                  in-state)))
              ((car err)
               (setq body (format "<h1>Error</h1><p>%s</p>" (car err))))
              ((car code)
               (spotify--log "Requesting a new access token...\n")
               (map-let (code-verifier redirect-uri) spotify--auth-challenge
                 (let ((data (spotify--retrieve-url-synchronously 
			       spotify--endpoint-token
                               :method "POST"
                               :data `(("grant_type"    "authorization_code")
                                       ("code"          ,(car code))
                                       ("redirect_uri"  ,redirect-uri)
                                       ("client_id"     ,spotify--client-id)
                                       ("code_verifier" ,code-verifier)))))
                   (map-let (("error" err) ("error_description" err_desc)) data
                     (if err
                         (progn
                           (setq body (format "<h1>Error</h1><p>%s</p>" err_desc))
                           (spotify--log "Request access token: error: %s: %s\n" err err_desc))
                       (spotify--log "Refresh access token: success!\n")
                       (setq spotify--auth-status 'authorized)
                       (spotify--delete-auth-redirect-process)
                       (spotify--set-token data)
                       (spotify--init-token-refresher)
                            (setq body
                             "<h1>Success!</h1><p>You may now return to Emacs. Check the logs if you have any issues.</p>")
                       (when spotify-close-page-on-auth-redirect
                         (setq head "<script>window.close()</script>"))
		       (when spotify-focus-on-auth-redirect
			 (x-focus-frame nil)))))))
              (t
               (setq body "<h1>Error</h1><p>No <code>code</code> in redirect.</p>")))))
    (concat "<html><head><title>Emacs Spotify></title>" head "</head><body>" body "</body></html>")))

(defun spotify--auth-redirect-filter (process data)
  "Process filter for network connections of `spotify--auth-redirect-process'.

Called when PROC receives new DATA."
  (with-current-buffer (spotify--auth-redirect-buffer process)
    (goto-char (point-max))
    (insert data)
    (when (> (line-number-at-pos) 1)
      (goto-char (point-min))
      (when (looking-at "^GET \\/\\?\\(.+\\) HTTP\\/1.1\r\n")
        (let* ((redirect-data (url-parse-query-string (match-string 1)))
               (html (spotify--handle-redirect-and-serve-html redirect-data))
               (http (concat "HTTP/1.1 200 OK\r\n"
                             "Server: Emacs Spotify\r\n"
                             "Connection: close\r\n"
                             "Content-Type: text/html\r\n"
                             (format "Content-Length: %d\r\n" (length html))
                             "\r\n"
                             html)))
          (process-send-string process http)))
      (process-send-eof)
      (delete-process)
      (kill-buffer))))

(defun spotify--init-auth-redirect-process ()
  "Initialize `spotify--auth-redirect-process'."
  (spotify--log "Initializing `spotify--auth-redirect-process'...\n")
  (spotify--delete-auth-redirect-process)
  (setq spotify--auth-redirect-process
        (make-network-process
         :name "Spotify Auth Redirect"
         :host 'local
         :service spotify-auth-redirect-port
         :family 'ipv4
         :filter #'spotify--auth-redirect-filter
         :server 2
         :noquery t)))

(defun spotify--delete-auth-redirect-process ()
  "Delete `spotify--auth-redirect-process' if it exists."
  (when (process-live-p spotify--auth-redirect-process)
    (spotify--log "Deleting `spotify--auth-redirect-process'...\n")
    (delete-process spotify--auth-redirect-process))
  (setq spotify--auth-redirect-process nil))

(defun spotify--set-token (data)
  "Set the access/refresh token given DATA.

DATA is the parsed JSON response received from requesting an access
token from `spotify--endpoint-token'.  This function can be called
for both the initial access token and for refreshing the access 
token with a refresh token because both use the same response format."
  (map-let (("access_token" access-token)
            ("expires_in" expires-in)
            ("refresh_token" refresh-token)) data
    (when (>= spotify-token-refresher-interval expires-in)
      (spotify--log "Warning: `spotify-token-refresher-interval' is %ds, but token expires in %ds\n"
                    spotify-token-refresher-interval
                    expires-in))
    (setq spotify--access-token access-token
          spotify--refresh-token refresh-token)))

(defun spotify--refresh-access-token ()
  "Retrieve a new access/refresh token using `spotify--refresh-token'."
  (spotify--log "Refresh access token: sending request...\n")
  (when spotify--refresh-token
    (spotify--retrieve-url spotify--endpoint-token
                           (lambda (_ data)
                             (if-let ((err (gethash "error" data)))
                                 (spotify--log "Refresh access token: error: %s\n"
                                               (gethash "error_description" data))
                               (spotify--log "Refresh access token: success!\n")
                               (spotify--set-token data)))
                           :method "POST"
                           :data `(("grant_type"    "refresh_token")
                                   ("refresh_token" ,spotify--refresh-token)
                                   ("client_id"     ,spotify--client-id)))))

(defun spotify--init-token-refresher ()
  "Initialize `spotify--token-refresher'."
  (spotify--log "Initializing `spotify--token-refresher'...\n")
  (spotify--delete-token-refresher)
  (setq spotify--token-refresher
        (run-at-time spotify-token-refresher-interval
                     spotify-token-refresher-interval
                     #'spotify--refresh-access-token)))

(defun spotify--delete-token-refresher ()
  "Delete `spotify--token-refresher' if it exists."
  (when spotify--token-refresher
    (spotify--log "Deleting `spotify--token-refresher'...\n")
    (cancel-timer spotify--token-refresher)
    (setq spotify--token-refresher nil)))

;;;; API-Related Functions

(defun spotify--error-check (data)
  "Assert that the json response in DATA does not contain an error."
  (map-let (("error" err) ("message" message)) data
    (when err
      (signal 'spotify--api-error (list message)))))

;;;; Interactive Functions

;;;###autoload
(defun start-spotify ()
  "Start Emacs Spotify and open a login page."
  (interactive)
  (if (eq spotify--auth-status 'authorized)
      (signal 'spotify--error '("already running, run `restart-spotify' to reload"))
    (when (eq spotify--auth-status 'unauthorized)
      (spotify--log "Starting Emacs Spotify...\n")
      (setq spotify--auth-status 'authorizing)
      (spotify--init-auth-redirect-process))
    (spotify--login)))

;;;###autoload
(defun stop-spotify ()
  "Stop Emacs Spotify."
  (interactive)
  (spotify--log "Stopping Emacs Spotify...\n")
  (spotify--delete-token-refresher)
  (setq spotify--refresh-token nil)
  (setq spotify--access-token nil)
  (spotify--delete-auth-redirect-process)
  (setq spotify--auth-challenge nil)
  (setq spotify--auth-status 'unauthorized))


;;;###autoload
(defun restart-spotify ()
  "Restart Emacs Spotify."
  (interactive)
  (stop-spotify)
  (start-spotify))

;;;###autoload
(defun spotify-next ()
  "Skip to next track in the user's queue.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/skip-users-playback-to-next-track'."
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
`https://developer.spotify.com/documentation/web-api/reference/skip-users-playback-to-previous-track'."
  (interactive)
  (let ((data (spotify--retrieve-url-synchronously
               spotify--endpoint-prev
               :method "POST"
               :headers (spotify--token-headers))))
    (spotify--error-check data)))

;;;###autoload
(defun spotify-play ()
  "Start a new context or resume current playback on the user's active device.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/start-a-users-playback'."
  (interactive)
  (let ((data (spotify--retrieve-url-synchronously
               spotify--endpoint-play
               :method "PUT"
               :headers (spotify--token-headers))))
    (spotify--error-check data)))

;;;###autoload
(defun spotify-pause ()
  "Pause playback on the user's account.

For more information, see:
`https://developer.spotify.com/documentation/web-api/reference/pause-a-users-playback'."
  (interactive)
  (let ((data (spotify--retrieve-url-synchronously
               spotify--endpoint-pause
               :method "PUT"
               :headers (spotify--token-headers))))
    (spotify--error-check data)))

(provide 'spotify)
;;; spotify.el ends here
