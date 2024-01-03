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

(eval-when-compile
  (require 'url-util)
  (require 'map))

;;;; Customization Variables

(defgroup spotify nil
  "Options for configuring the Emacs Spotify service."
  :group 'applications)

(defcustom spotify-keymap-prefix "M-s"
  "The prefix key for all Emacs Spotify key bindings.

Set to nil to disable the default Emacs Spotify keymaps."
  :type 'key
  :group 'spotify)

(defgroup spotify-log nil
  "Options for configuring the logging system."
  :group 'spotify)

(defcustom spotify-enable-logging nil
  "Non-nil if the logging system should be enabled."
  :type 'boolean
  :group 'spotify-log)

(defcustom spotify-log-buffer-name "*Spotify Log*"
  "The name of the buffer in which messages should be logged."
  :type 'string
  :group 'spotify-log)

(defcustom spotify-log-prefix "[%x %X] "
  "The prefix of the messages in the log.

This string should be compatible with `format-time-string'."
  :type 'string
  :group 'spotify-log)

(defgroup spotify-auth nil
  "Options for configuring authorization."
  :group 'spotify)

(defcustom spotify-token-refresher-interval 3000
  "How often `spotify--token-refresher' should repeat, in seconds."
  :type 'natnum
  :group 'spotify-auth)

(defcustom spotify-auth-redirect-port 8080
  "The port that `spotify--auth-redirect-process' should bind to.

Due to how the Emacs Spotify is configured in the Spotify dashboard, only a
handful of ports will actually work.  If you want to choose a different port,
please contact me by submitting an issue to GitHub, since it's pretty easy for
me to add new alternative ports."
  :type '(choice (const 80)
                 (const 8000)
                 (const 8080)
                 (const 8888)
                 (const 42069))
  :group 'spotify-auth)

(defcustom spotify-close-page-on-auth-redirect t
  "Whether the browser should close the page after the Spotify login process.

May not work on some browsers."
  :type 'boolean
  :group 'spotify-auth)

(defcustom spotify-focus-on-auth-redirect nil
  "Whether Emacs should try to take focus back after the Spotify login process."
  :type 'boolean
  :group 'spotify-auth)

(defcustom spotify-auth-lost-behavior :relog-interactive
  "What to do if an access token somehow expires or fails to refresh.

 - Relog: Open a new \"Login with Spotify\" page.
 - Relog if interactive: Open a new \"Login with Spotify\" page if the user
   enter a command causing the failure, but not if the token fails to refresh
   (this would happen in the background).
 - Error: Send an error message and do nothing to resolve it."
  :type '(choice (const :tag "Relog" :relog)
                 (const :tag "Relog if interactive" :relog-interactive)
                 (const :tag "Error" :error))
  :group 'spotify-auth)

;;;; Constants

(defconst spotify--client-id "ee9e6d2cdba8448f9fadfbf85678273e"
  "The Client ID for the Emacs Spotify SDA.")

(defconst spotify--endpoint-auth "accounts.spotify.com/authorize"
  "Spotify API endpoint: authorization.")

(defconst spotify--endpoint-token "accounts.spotify.com/api/token"
  "Spotify API endpoint: access token.")

(defconst spotify--endpoint-next "api.spotify.com/v1/me/player/next"
  "Spotify API endpoint: skip to next.")

(defconst spotify--endpoint-prev "api.spotify.com/v1/me/player/previous"
  "Spotify API endpoint: skip to previous.")

(defconst spotify--endpoint-play "api.spotify.com/v1/me/player/play"
  "Spotify API endpoint: start/resume playback.")

(defconst spotify--endpoint-pause "api.spotify.com/v1/me/player/pause"
  "Spotify API endpoint: pause playback.")

(defconst spotify--scopes '("user-modify-playback-state")
  "The set of required permissions.

As long as you keep `spotify--access-token' and`spotify--refresh-token' secure
on your machine, these permissions are not accessible to anyone except yourself.")

(define-error 'spotify--error
              "Spotify"
              'error)

(define-error 'spotify--api-error
              "Spotify API"
              'spotify--error)

;;;; Global Variables

(defvar spotify--auth-status 'unauthorized
  "Enum representing the authorization status.

 - authorized: The user hasn't started the authorization process yet.
 - authorizing: The user has been prompted to login, awaiting a response.
 - authorized: The user has authorized Emacs Spotify, access token available.")

(defvar spotify--auth-challenge nil
  "Oauth2 PKCE challenge generated during auth.

Represented as an symbol-to-value alist:
  ((code-verifier  . randomly generated string)
   (code-challenge . base64 encoded code-verifier [A-Za-z_-]+)
   (redirect-uri   . http://localhost:[port]/)
   (state          . randomly generated string)).")

(defvar spotify--auth-redirect-process nil
  "Mini HTTP server to handle redirects from the \"Login with Spotify\" page.")

(defvar spotify--access-token nil
  "Token for making API requests.")

(defvar spotify--refresh-token nil
  "Token for refreshing `spotify--access-token'.")

(defvar spotify--token-refresher nil
  "Timer for refreshing `spotify--access-token'.

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
  "Log a message into `spotify-log-buffer-name'.

The message that will be logged is the concatenation of `spotify-log-prefix'
formatted with `format-time-string' and `format` applied to MESSAGE and ARGS.

If `spotify-enable-logging' is nil, nothing will happen."
  (when spotify-enable-logging
    (with-current-buffer (get-buffer-create spotify-log-buffer-name)
      (goto-char (point-max))
      (insert
       (format-time-string spotify-log-prefix)
       (apply #'format message args)
       "\n"))))

(defun spotify--browse-url (endpoint &optional query-string)
  "Build a formatted HTTPS URL given an ENDPOINT and a QUERY-STRING.

QUERY-STRING should be compatible with `url-build-query-string'."
  (browse-url
   (concat "https://" endpoint "?" (url-build-query-string query-string))))

(defun spotify--parse-http-response ()
  "Parse the content of the HTTP response in the current buffer.

The current buffer should have been generated by `url-retrieve-synchronously' or
`url-retrieve."
  (let* ((content-type (eval 'url-http-content-type))
         (content      (buffer-substring (1+ (eval 'url-http-end-of-headers))
                                         (point-max)))
         (status       (eval 'url-http-response-status)))
    (cond ((not content-type))
          ((string-match-p "^\\s *application/json\\s *\\(;.*\\)?$"
                           content-type)
           (setq content-type 'json)
           (setq content (json-parse-string content))))
    `((content-type . ,content-type)
      (content      . ,content)
      (status       . ,status))))

(defun spotify--fetch-async (endpoint callback &rest args)
  "Wrapper around `url-retrieve'.
  
Sends an asynchronous HTTPS request to ENDPOINT, and calls CALLBACK once a
response is received.
ARGS is a plist with the following optional fields:
 - :method is for `url-request-method'
 - :headers is for `url-request-extra-headers',
   (\"Content-Type: application/x-www-form-urlencoded\") is automatically added
 - :data is for `url-request-data', passes through `url-build-query-string'

The following function call and cURL command are equivalent:

  (spotify--fetch-async \"example.com\"
                        :method \"XXXX\"
                        :headers ((ka . va) (kb . vb))
                        :data ((kc vc) (kd vd)))

  curl -X \"XXXX\" -H \"Content-Type: application/x-www-form-urlencoded\"
       -H \"ka: va\" -H \"kb: vb\" -d \"kc=vc&kd=vd\"
       \"https://example.com\"."
  (let ((url-request-method        (plist-get args :method))
        (url-request-extra-headers (cons '("Content-Type" . "application/x-www-form-urlencoded")
                                         (plist-get args :headers)))
        (url-request-data          (when (plist-member args :data)
                                     (url-build-query-string (plist-get args :data)))))
    (spotify--log "Sending HTTP request to \"%s\"...\n - method: %s\n - headers: %s\n%s\n"
                  endpoint
                  url-request-method
                  url-request-extra-headers
                  url-request-data)
    (url-retrieve (concat "https://" endpoint)
                  (lambda (_)
                    (let ((response (spotify--parse-http-response)))
                      (map-let (content status) response
                        (spotify--log
                         "Retrieved HTTP response from \"%s\"\n - status: %s\n%s\n"
                         args
                         status
                         content))
                      (when callback
                        (funcall callback response))))
                  nil
                  t
                  t)))

(defun spotify--fetch (endpoint &rest args)
  "Wrapper around `url-retrieve-synchronously'.
  
See docs for `url-retrieve' for how ENDPOINT and ARGS work."
  (let ((response (let ((url-request-method        (plist-get args :method))
                        (url-request-extra-headers (cons '("Content-Type" .
                                                           "application/x-www-form-urlencoded")
                                                         (plist-get args :headers)))
                        (url-request-data          (url-build-query-string (plist-get args :data))))
                    (spotify--log
                     "Sending HTTP request to \"%s\"...\n - method: %s\n - headers: %s\n%s\n"
                     endpoint
                     url-request-method
                     url-request-extra-headers
                     url-request-data)
                    (with-current-buffer (url-retrieve-synchronously (concat "https://" endpoint)
                                                                     t
                                                                     t)
                      (spotify--parse-http-response)))))
    (map-let (content status) response
      (spotify--log "Retrieved HTTP response from \"%s\"\n - status: %d\n%s\n"
                    endpoint
                    status
                    content))
    response))

(defun spotify--token-headers ()
  "Create the necessary headers to perform an API request with an access token."
  (if spotify--access-token
      (list (cons "Authorization" (concat "Bearer " spotify--access-token)))
    (signal 'spotify--error '("token is nil, run `spotify-start' first"))))

;;;; Authorization Functions

(defun spotify--login ()
  "Open a \"Login with Spotify\" page in the browser.

In addition, generate a new PKCE challenge and store it into
`spotify--auth-challenge' to begin the authorization process."
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
                         `((client_id             ,spotify--client-id)
                           (response_type         code)
                           (redirect_uri          ,redirect-uri)
                           (state                 ,state)
                           (scope                 ,(string-join spotify--scopes " "))
                           (code_challenge_method S256)
                           (code_challenge        ,code-challenge)))))

(defun spotify--auth-redirect-buffer (process)
  "Buffer for a network connection PROCESS of `spotify--auth-redirect-process'."
  (or (process-buffer process)
      (set-process-buffer
       process
       (get-buffer-create (concat " *" (process-name process) "* ")))))

(defun spotify--handle-redirect-and-serve-html (redirect-data)
  "Handle REDIRECT-DATA coming from a redirect to `spotify--auth-redirect-process'.

Initialize access token using info from REDIRECT-DATA if possible.
Return an HTML response after processing the data."
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
                 (let ((response (spotify--fetch spotify--endpoint-token
                                                 :method "POST"
                                                 :data `((grant_type    authorization_code)
                                                         (code          ,(car code))
                                                         (redirect_uri  ,redirect-uri)
                                                         (client_id     ,spotify--client-id)
                                                         (code_verifier ,code-verifier)))))
                   (map-let (content) response
                     (map-let (("error" err) ("error_description" err_desc)) content
                       (if err
                           (progn
                             (setq body (format "<h1>Error</h1><p>%s</p>" err_desc))
                             (spotify--log "Request access token: error: %s: %s\n" err err_desc))
                         (spotify--log "Request access token: success!\n")
                         (setq spotify--auth-status 'authorized)
                         (spotify--delete-auth-redirect-process)
                         (spotify--set-token content)
                         (spotify--init-token-refresher)
                         (setq body
                               (concat
                                "<h1>Success!</h1>"
                                "<p>You may now return to Emacs. "
                                "Check the logs if you have any issues.</p>"))
                         (when spotify-close-page-on-auth-redirect
                           (setq head "<script>window.close()</script>"))
                         (when spotify-focus-on-auth-redirect
                           (x-focus-frame nil))))))))
              (t
               (setq body "<h1>Error</h1><p>No <code>code</code> in redirect.</p>")))))
    (concat "<html><head><title>Emacs Spotify</title>" head "</head><body>" body "</body></html>")))

(defun spotify--auth-redirect-filter (process data)
  "Process filter for network connections of `spotify--auth-redirect-process'.

Called when PROCESS receives new DATA."
  (with-current-buffer (spotify--auth-redirect-buffer process)
    (goto-char (point-max))
    (insert data)
    (when (> (line-number-at-pos) 1)
      (goto-char (point-min))
      (when (looking-at "^GET /\\?\\(.+\\) HTTP/1.1\r\n")
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

DATA is the parsed JSON response received by requesting an access token from
`spotify--endpoint-token'.  This function can be called with the JSON response
from requesting the initial access token and from refreshing the access token
with a refresh token because both use the same response format."
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
    (spotify--fetch-async spotify--endpoint-token
                          (lambda (response)
                            (map-let (content status) response
                              (if (and (eq 401 status)
                                       (eq :relog spotify-auth-lost-behavior))
                                  (restart-spotify)
                                (if-let ((err (gethash "error" content)))
                                    (spotify--log "Refresh access token: error: %s\n"
                                                  (gethash "error_description" content))
                                  (spotify--log "Refresh access token: success!\n")
                                  (spotify--set-token content)))))
                          :method "POST"
                          :data `((grant_type    refresh_token)
                                  (refresh_token ,spotify--refresh-token)
                                  (client_id     ,spotify--client-id)))))

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

Bound to `spotify-keymap-prefix' when `spotify-mode' is enabled.

You can customize this by setting it to a different value in your init file.
Alternatively, if you don't want to use `spotify-keymap-prefix' at all, you can
set `spotify-keymap-prefix' to nil and then bind the keys as you see fit.")

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

;;;; API-Related Functions

(defun spotify--error-check (response)
  "Assert that the API RESPONSE does not contain an error.

Throws error or returns non-nil on failure."
  (map-let (content-type content status) response
    (cond ((and (eq 401 status)
                (or (eq :relog spotify-auth-lost-behavior)
                    (eq :relog-interactive spotify-auth-lost-behavior)))
           (restart-spotify)
           t)
          ((eq 'json content-type)
           (when-let ((err (gethash "error" content))
                      (err-message (gethash "message" err)))
             (signal 'spotify--api-error (list err-message)))))))

;;;; Interactive Functions

;;;###autoload
(defun start-spotify ()
  "Start the Emacs Spotify service and open a login page."
  (interactive)
  (if (eq spotify--auth-status 'authorized)
      (signal 'spotify--error '("already running, run `restart-spotify' to reload"))
    (when (eq spotify--auth-status 'unauthorized)
      (spotify--log "Starting Emacs Spotify service...\n")
      (setq spotify--auth-status 'authorizing)
      (spotify--init-auth-redirect-process))
    (spotify--login))
  (spotify-mode 1))

;;;###autoload
(defun stop-spotify ()
  "Stop the Emacs Spotify service."
  (interactive)
  (spotify--log "Stopping Emacs Spotify service...\n")
  (spotify--delete-token-refresher)
  (setq spotify--refresh-token nil)
  (setq spotify--access-token nil)
  (spotify--delete-auth-redirect-process)
  (setq spotify--auth-challenge nil)
  (setq spotify--auth-status 'unauthorized)
  (spotify-mode -1))


;;;###autoload
(defun restart-spotify ()
  "Restart the Emacs Spotify service."
  (interactive)
  (stop-spotify)
  (start-spotify))

;;;###autoload
(defun spotify-next ()
  "Skip to next track in the user's queue."
  (interactive)
  (let ((response (spotify--fetch spotify--endpoint-next
                                  :method "POST"
                                  :headers (spotify--token-headers))))
    (spotify--error-check response)))

;;;###autoload
(defun spotify-prev ()
  "Skips to previous track in the user’s queue."
  (interactive)
  (let ((response (spotify--fetch spotify--endpoint-prev
                                  :method "POST"
                                  :headers (spotify--token-headers))))
    (spotify--error-check response)))

;;;###autoload
(defun spotify-play ()
  "Start a new context or resume current playback on the user's active device."
  (interactive)
  (let ((response (spotify--fetch spotify--endpoint-play
                                  :method "PUT"
                                  :headers (spotify--token-headers))))
    (spotify--error-check response)))

;;;###autoload
(defun spotify-pause ()
  "Pause playback on the user's account."
  (interactive)
  (let ((response (spotify--fetch spotify--endpoint-pause
                                  :method "PUT"
                                  :headers (spotify--token-headers))))
    (spotify--error-check response)))

(provide 'spotify)
;;; spotify.el ends here
