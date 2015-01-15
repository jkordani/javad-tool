;;;; javad-tool.lisp

(in-package #:javad-tool)

;;; "javad-tool" goes here. Hacks and glory await!


(defun javad-login (stream)
  "Reads from a given stream until the password is scarfed from the header"
  (let* ((header (read-until stream "login: "))
	(password (subseq (cl-ppcre:scan-to-strings "id=(.*),ver" header) 21 28)))
    (format stream "~C~C~a~C~C" #\return #\linefeed password #\return #\linefeed)
    (force-output stream)))

(defun javad-read (is)
  (with-output-to-string (s)
    (do ((c (read-char-no-hang is) (read-char-no-hang is nil 'the-end)))
	((not (characterp c)))
      (format s "~A" c))))

(defun read-until (is regex)
  (let* ((capture (make-array 256 :element-type 'character :fill-pointer 0 :adjustable t)))
    (do ((c (read-char-no-hang is) (read-char-no-hang is nil 'the-end)))
	((cl-ppcre:scan-to-strings regex capture) capture)
      (if (characterp c) (vector-push-extend c capture)))))


(defun javad-read-header (is)
  (let ((string (make-array 64 :element-type 'character :fill-pointer 0 :adjustable t)))
    (do ((c (read-char-no-hang is) (read-char-no-hang is nil 'the-end)))
	((not (characterp c)))
      (if (characterp c)
	  (vector-push c string)))
    string))

(defun javad-connect (host &optional (port 8002))
  (let* ((socket  (ccl:make-socket :remote-host host :remote-port port))
	 ;(echo-stream (make-echo-stream socket *standard-output*))
	 )
    (javad-login socket)
    socket))



(defun javad-generic-command (stream command)
  (format stream "~a~C~C" command #\return #\linefeed)
  (force-output stream))

(defclass javad-generic-message ()
  ((type
    :initarg :type)
   (length
    :initarg :length
    :initform 0)
   (data
    :initarg :data)))

(defun javad-parse-message (is)
  (let ((message (make-instance 'javad-generic-message)))
    (with-slots (type length) message
      (setf type (format nil "~a~a" (read-char is) (read-char is)))
      (setf length (parse-integer (format nil "~a~a~a" (read-char is) (read-char is) (read-char is)) :radix 16))
      (setf (slot-value message 'data) (make-array length :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t))
      (dotimes (j length)
	(vector-push (read-byte is) (slot-value message 'data)))
      message)))

(defun javad-parse-vg-message (vg-message)
  ; remember to check endianness with MT messsage, format is 4f latvel 4f lonvel 4f altvel 4f velsep 1u soltype 1u cs,  assume lsb and also modifies data slot in place
  (let ((offset 0)
	(vals (make-array 6 :fill-pointer 0))
	(val 0 )
	(data (slot-value vg-message 'data)))
    (dotimes (j 4)
      (setf val 0)
      (setf (ldb (byte 8 0)  val) (elt data (+ 0 offset)))
      (setf (ldb (byte 8 8)  val) (elt data (+ 1 offset)))
      (setf (ldb (byte 8 16) val) (elt data (+ 2 offset)))
      (setf (ldb (byte 8 24) val) (elt data (+ 3 offset)))
      (setf offset (+ 4 offset))
      (vector-push (ie3fp:decode-ieee-float val) vals))
    (vector-push (elt data offset)     vals)
    (vector-push (elt data (1+ offset)) vals)
    (setf (slot-value vg-message 'data) vals)
    vg-message))


(defun javad-get-velocity (is)
  ; assumes logged in javad on input stream
  (javad-read is)
  (javad-generic-command is "out,,/msg/jps/VG")
  (let ((message (javad-parse-vg-message (javad-parse-message is))))
    (javad-read is)
    (slot-value message 'data)))
