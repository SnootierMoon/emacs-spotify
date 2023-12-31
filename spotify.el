;;; spotify.el --- Control Spotify -*- lexical-binding: t -*-

;; Copyright (C) 2020 Akshay Trivedi

;; Author: Akshay Trivedi <aku24.7x3@gmail.com>
;; Maintainer: Akshay Trivedi <aku24.7x3@gmail.com>
;; Version: 0.0.1
;; Created: 9 Aug 2020
;; Keywords: hypermedia
;; Package-Requires: ((emacs "27.1") (simple-httpd "1.5.1"))
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

;;; Code:

;;;; Requires

(require 'simple-httpd)

;;;; Constants

(defconst spotify--client-id "ee9e6d2cdba8448f9fadfbf85678273e")
(defconst spotify--endpoint-auth  "accounts.spotify.com/authorize")
(defconst spotify--endpoint-token "accounts.spotify.com/api/token")
(defconst spotify--endpoint-next  "api.spotify.com/v1/me/player/next")
(defconst spotify--endpoint-prev  "api.spotify.com/v1/me/player/previous")
(defconst spotify--endpoint-play  "api.spotify.com/v1/me/player/play")
(defconst spotify--endpoint-pause "api.spotify.com/v1/me/player/pause")

(defconst spotify--scopes '("user-modify-playback-state")
  "The list of OAuth2 scopes.")

(define-error 'spotify--error "Spotify: error" 'error)
(define-error 'spotify--no-token-error "Spotify: token is nil." 'spotify--error)
(define-error 'spotify--invalid-uri-error "Spotify: Invalid Spotify URI" 'spotify--error)

;;;; Customization Variables

(defgroup spotify nil
  "Spotify Customization Group."
  :group 'applications)

(defcustom spotify-keymap-prefix "M-s"
  "The prefix for Spotify keybindings."
  :group 'spotify
  :type 'string)

(defcustom spotify-enable-logging t
  "Non-nil if Spotify should log messages in the Spotify Log Buffer."
  :group 'spotify
  :type 'boolean)

(defcustom spotify-log-buffer-name "*Spotify Log*"
  "The name of the Spotify Log Buffer."
  :group 'spotify
  :type 'string)

(defcustom spotify-log-prefix "[%r]: "
  "The prefix of the messages in the Spotify Log Buffer.

The string should be compatible with `format-time-string'."
  :group 'spotify
  :type 'string)

(defcustom spotify-token-refresher-delay 60
  "How often `spotify--token-refresher' should repeat, in seconds."
  :group 'spotify
  :type 'string)

(defcustom spotify-stops-httpd t
  "Non-nil if `httpd-stop' should be called when `spotify-stop' is called."
  :group 'spotify
  :type 'boolean)

;;;; Global State Variables

(defvar spotify--challenge nil
  "Data necessary for authorization.")


(defvar spotify--access-token nil
  "The token used for authentication.")

(defvar spotify--refresh-token nil
  "The token used to refresh `spotify--access-token'.")

(defvar spotify--token-refresher nil
  "The timer that periodically refreshes `spotify--access-token'.")

(defvar spotify--keymap
  (let ((map (make-keymap)))
    (define-key map (kbd "g") #'spotify-play)
    (define-key map (kbd "G") #'spotify-pause)
    (define-key map (kbd "f") #'spotify-next)
    (define-key map (kbd "n") #'spotify-next)
    (define-key map (kbd "b") #'spotify-prev)
    (define-key map (kbd "p") #'spotify-prev)
    map)
  "Spotify keymap.

Gets bound to `spotify--keymap-prefix' when `spotify-mode' is enabled.")

(define-minor-mode spotify-mode
  "Toggle the Spotify minor mode.

Enable Spotify keybindings."
  :group 'spotify
  :global t
  :keymap (make-sparse-keymap)
  (spotify--init-keymap))

(defun spotify--init-keymap ()
  "Reset the Spotify keymap."
  (setq spotify-mode-map (make-sparse-keymap))
  (define-key spotify-mode-map (kbd spotify-keymap-prefix) spotify--keymap))

;;;; Utility Functions

(defun spotify--random-char (charset)
  "Return a character from CHARSET."
  (elt charset (random (length charset))))

(defun spotify--random-string (charset length)
  "Return a string of characters in CHARSET with a size of LENGTH."
  (apply #'string (mapcar #'spotify--random-char (make-list length charset))))

(defun spotify--log (string &rest args)
  "Log a message into the Spotify Log Buffer.

STRING and ARGS gets passed into `format', and `spotify-log-prefix' is
prepended to the message."
  (when spotify-enable-logging
    (with-current-buffer (get-buffer-create spotify-log-buffer-name)
      (goto-char (point-max))
      (insert spotify-log-prefix
	      (apply #'format (cons string args))
	      "\n"))))

(defun spotify--url-format (endpoint query-params)
  "Format ENDPOINT and QUERY-PARAMS into a url and return it."
  (if query-params
      (format "https://%s?%s" endpoint (url-build-query-string query-params))
    (format "https://%s" endpoint)))

(defun spotify--url-browse (endpoint &optional query-params)
  "Format ENDPOINT and QUERY-PARAMS into a url and open it in a browser."
  (let ((full-url (spotify--url-format endpoint query-params)))
    (spotify--log "Opening %s in the browser" full-url)
    (browse-url full-url)))


(defun spotify--url-retrieve (endpoint callback &rest args)
  "Convenience wrapper over `url-retrieve'.

Sends the request to ENDPOINT.
Calls CALLBACK when a response is recieved.
ARGS is a plist that can have :method, :data, :headers, and :params
 - :method is `url-request-method' (\"GET\" by default).
 - :data is `url-request-data'.
 - :headers is `url-request-extra-headers'
     (automatically adds \"Content-Type: application/x-www-form-urlencoded\")
 - :params is Query Parameters."
  (let ((url-request-method        (plist-get args :method))
        (url-request-data          (url-build-query-string (plist-get args :data)))
        (url-request-extra-headers (plist-get args :headers)))
    (push '("Content-Type" . "application/x-www-form-urlencoded") url-request-extra-headers)
    (spotify--log "Retrieving from URL: %s" endpoint)
    (url-retrieve (spotify--url-format endpoint (plist-get args :params))
                  (lambda (_)
		    (let ((data (buffer-substring (1+ (eval 'url-http-end-of-headers)) (point-max))))
		      (spotify--log "Got response from %s: %s" endpoint data)
		      (when callback (funcall callback data))))
                  nil t)))

(defmacro with-access-token (&rest body)
  "Run BODY if the access token exists, error if it doesn't."
  `(if spotify--access-token
       ,@body
     (signal 'spotify--no-token-error nil)))

;;;; Authorization Functions

(defun spotify--challenge-new ()
  "Generate a PKCE challenge and store it in `spotify--challenge'."
  (let* ((code-verifier      (spotify--random-string "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~" 64))
         (code-challenge     (secure-hash 'sha256 code-verifier nil nil t))
         (code-challenge-b64 (base64url-encode-string code-challenge t))
         (redirect-uri       (format "http://localhost:%d/emacs-spotify-login/" httpd-port))
         (scope              (string-join spotify--scopes " "))
         (state              (spotify--random-string "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 32)))
    (spotify--log "Creating a new PKCE challenge")
    (setq spotify--challenge `((code-challenge . ,code-challenge-b64)
                               (code-verifier  . ,code-verifier)
                               (redirect-uri   . ,redirect-uri)
                               (scope          . ,scope)
                               (state          . ,state)))))

(defun spotify--login ()
  "Open a \"Login with Spotify\" page."
  (spotify--challenge-new)
  (map-let (code-challenge redirect-uri scope state) spotify--challenge
    (spotify--url-browse spotify--endpoint-auth
			 `(("client_id"             ,spotify--client-id)
			   ("code_challenge"        ,code-challenge)
			   ("code_challenge_method" "S256")
			   ("redirect_uri"          ,redirect-uri)
			   ("response_type"         "code")
			   ("scope"                 ,scope)
			   ("state"                 ,state)))))

(defun spotify--token-new (data)
  "Create a new Spotify access/refresh token given DATA."
  (map-let (access_token error refresh_token) data
    (setq spotify--access-token `(("Authorization" . , (concat "Bearer " access_token))))
    (setq spotify--refresh-token refresh_token)
    (ignore error)))


(defun spotify--token-refresher-new ()
  "Create a new Spotify token refresher."
  (spotify--token-refresher-delete)
  (setq spotify--token-refresher
        (run-at-time t spotify-token-refresher-delay #'spotify--token-refresh)))

(defun spotify--token-refresher-delete ()
  "Delete the current Spotify token refresher if it exists."
  (when spotify--token-refresher
    (cancel-timer spotify--token-refresher)
    (setq spotify--token-refresher nil)))

(defun spotify--token-request (code)
  "Request a new Spotify access/refresh token using CODE and create a refresher."
  (map-let (code-verifier redirect-uri) spotify--challenge
    (spotify--url-retrieve spotify--endpoint-token
			   (lambda (response)
			     (spotify--token-new (json-read-from-string response))
			     (spotify--token-refresher-new))
			   :method "POST"
			   :data `(("client_id"     ,spotify--client-id)
                                   ("code"          ,code)
                                   ("code_verifier" ,code-verifier)
                                   ("grant_type"    "authorization_code")
                                   ("redirect_uri"  ,redirect-uri)))))

(defun spotify--token-refresh ()
  "Requests a new Spotify access/refresh token using the refresh token."
  (when spotify--refresh-token
    (spotify--url-retrieve spotify--endpoint-token
			   (lambda (response)
			     (spotify--token-new (json-read-from-string response)))
                           :method "POST"
                           :data `(("client_id"     ,spotify--client-id)
                                   ("grant_type"    "refresh_token")
                                   ("refresh_token" ,spotify--refresh-token)))))

(defservlet* emacs-spotify-login text/html (code error state)
  (cond ((not (string= state (alist-get 'state spotify--challenge)))
         (insert "Invalid state. Try logging in with Spotify again."))
        (error (insert "Error: " error))
        (t (insert
	    "<html>"
	    "<script>window.close()</script>"
	    "<body>"
	    "<p>Sucess. You may now return to Emacs. Check the logs if you have any issues.</p>"
	    "<button class=\"closeButton\" style=\"cursor: pointer\" onclick=\"window.close();\">Close Window</button>"
	    "</body>"
	    "</html>")
	   (spotify--token-request code))))

;;;; Interactive Functions

;;;###autoload
(defun spotify-start ()
  "Initialize Spotify.

Starts an HTTP Server and starts the PKCE authorization flow."
  (interactive)
  (unless (httpd-running-p)
    (httpd-start))
  (spotify--login)
  (spotify-mode))

;;;###autoload
(defun spotify-stop ()
  "Stop Spotify and free resources."
  (interactive)
  (spotify--token-refresher-delete)
  (when spotify-stops-httpd
    (httpd-stop)))

;;;###autoload
(defun spotify-next ()
  "Go to the next song in the playback."
  (interactive)
  (with-access-token
   (spotify--url-retrieve spotify--endpoint-next
			  #'ignore
			  :method "POST"
			  :headers spotify--access-token)))

;;;###autoload
(defun spotify-prev ()
  "Go to the previous song in the playback."
  (interactive)
  (with-access-token
   (spotify--url-retrieve spotify--endpoint-prev
			  #'ignore
			  :method "POST"
			  :headers spotify--access-token)))

;;;###autoload
(defun spotify-play ()
  "Play the current song in the playback."
  (interactive)
  (with-access-token
   (spotify--url-retrieve spotify--endpoint-play
			  #'ignore
			  :method "PUT"
			  :headers spotify--access-token)))

;;;###autoload
(defun spotify-pause ()
  "Pause the current song in the playback."
  (interactive)
  (with-access-token
   (spotify--url-retrieve spotify--endpoint-pause
			  #'ignore
			  :method "PUT"
			  :headers spotify--access-token)))

(provide 'spotify)
;;; spotify.el ends here
