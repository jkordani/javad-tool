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

#+ccl
(defun javad-connect (host &optional (port 8002))
  (let* ((socket  (ccl:make-socket :remote-host host :remote-port port))
	 ;(echo-stream (make-echo-stream socket *standard-output*))
	 )
    (javad-login socket)
    socket))

(defun packets-from-pcap (filename &key (limit -1))
  (plokami:with-pcap-reader (pcap filename :snaplen 1500)
    (let ((timestamps nil))
      (plokami:capture pcap limit
		       (lambda (sec usec caplen len buffer)
			 ;; Packet processing code here
			 ;; (format t "Packet length: ~A bytes, on the wire: ~A bytes ~D~%"
			 ;; 	      caplen
			 ;; 	      len
			 ;; 	      (ubin::coerce-seq-to-numeric (subseq buffer 1242 1246)))
			 (push (subseq buffer 0 1500) timestamps)))
      (reverse timestamps))))

(defun packets-to-messages (packets)
  (loop for packet in packets
		      ;; do (break)
	for pos = (search (ccl:encode-string-to-octets "~~") packet)
	;; do (break)
	unless (null pos)
	  append (loop  for message = (ccl:with-input-from-vector (msgvec (subseq packet pos))
					(javad-parse-message msgvec))
			do (setf pos (cl-ppcre:scan "[a-zA-Z]{2}[a-eA-E0-9]{3}" (ccl:decode-string-from-octets packet) :start (+ pos 1 (slot-value message 'length))))
			until (null pos)
			until (equal "::" (slot-value message 'type)) ;find epoch end
			collect message)))

(defun lists-to-csv (pathname lists)
  (with-open-file (outfile pathname :direction :output
				    :if-exists :supersede)
    (loop for entry in lists
	  do (format outfile "~{~A~^,~}~%" entry))))


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
      (setf length (parse-integer (format nil "~a~a~a" (read-char is) (read-char is) (read-char is)) :radix 16 :junk-allowed nil))
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

(defun javad-parse-ar-message (ar-message)
  ;;remember to check for endianness.  format is
  ;;u4 time, f4 pitch,roll,heading,pitchRMS,rollRMS,headingRMS
  ;;u1 flags,checksum
  ;; returns data as alist
  (let ((data (slot-value ar-message 'data))
	(tempvals nil)
	(returnvals nil)
	(offset 0)
	(val 0))
    (dotimes (j 7)
      (setf val 0)
      (setf (ldb (byte 8 0)  val) (elt data (+ 0 offset)))
      (setf (ldb (byte 8 8)  val) (elt data (+ 1 offset)))
      (setf (ldb (byte 8 16) val) (elt data (+ 2 offset)))
      (setf (ldb (byte 8 24) val) (elt data (+ 3 offset)))
      (setf offset (+ 4 offset))
      (push val tempvals))
    (dotimes (j 2)
     (push (elt data (+ offset j)) tempvals))
    (setf tempvals (nreverse tempvals))
    (setf tempvals (cons (car tempvals)
			 (append (mapcar #'ie3fp:decode-ieee-float (subseq tempvals 1 7))
				 (last tempvals 2))))
    tempvals))

(defun javad-get-velocity (is)
  ; assumes logged in javad on input stream
  (javad-read is)
  (javad-generic-command is "out,,/msg/jps/VG")
  (let ((message (javad-parse-vg-message (javad-parse-message is))))
    (javad-read is)
    (slot-value message 'data)))

;;make struct of block before, fill it out, post process with last block type for dataleng vs seq
(defun dtp-transmitter-prep (data &key (block-size 512) (block-num 0) (crc 0))
  "Data should be byte vector, returns alist of blocks, data checksum?"
  (if (/= (length data) 0)
      (if (< (length data) block-size)
	  (let ((orig-length (length data))
		(data (concatenate 'vector data 
				   (make-array (- block-size (length data)) 
					       :initial-element 0)))) 
	    (cons (list #x04
			orig-length
			data
			(crc16-lisp data)
			#x03) 
		  nil))
	  (let* ((block-data (subseq data 0 block-size))
		 (new-crc (crc16-lisp block-data))
		 (type (if (= block-size (length data))
			   #x04
			   #x02)))
	    (cons (list type
			(if (= type #x04)
			    (length data)
			    block-num)
			block-data 
			new-crc
			#x03)
		  (dtp-transmitter-prep (subseq data block-size)
					:block-size block-size
					:block-num (1+ block-num)
					:crc new-crc))))))

(defun dtp-receiver (stream &key (state '(:init t :task ack)))
  (let ((type nil))
    (cond 
      ((getf state :init) (setf (getf state :init) nil)
       (setf (getf state :task) 'rcv)
       (setf (getf state :blocks) nil)
       (setf (getf state :next-block) 0)
       (setf (getf state :continue) t)
       (write-byte #x15 stream) ;nack to init transfer
       )
     
      ((equal (getf state :task) 'ack) 
       (write-byte #x06 stream)
       (setf (getf state :task) 'rcv)
       (setf (getf state :continue) t)
       (1+ (getf state :next-block)))
      
      ((equal (getf state :task) 'rcv)
       (princ "inner rcv")
       (setf (getf state :task) 'ack)
       (setf type (read-byte stream))
       (setf (getf state :blocks) (append (getf state :blocks) (list type
								     (read-byte stream)
								     (read-byte stream))))
       (if (= type #x02)
	   (setf (getf state :continue) t)
	   (setf (getf state :continue) nil)))))
  state)

(defun dtp-transmitter (stream &key state)
  ;assumes blocks are loaded in state
  (let ((rcv-ack (read-byte stream))
	(block nil))
    (cond 
      ((and (getf state :init)
	    (equal rcv-ack 'nack))
       (setf (getf state :init) nil)
       (setf (getf state :next-block) 0))
      (t (1+ (getf state :next-block))))

    (setf block (nth (getf state :next-block) (getf state :blocks)))
    (write-byte (car block) stream)
    (write-byte (cadr block) stream)
    (write-byte (caddr block) stream)
    state))

(defun dtp-trans-receive (data &key (blocksize 512)) ;need to send ack then read ack then send block then read block, and... can't be in the same file...???
  (ccl:with-open-soclet (trans-socket) :local-port 8002
			:connect :passive
			(ccl:with-open-socket (recv-socket) :remote-port 8002
)
			(let* (
			       ;; (stream (open "/tmp/pipe" :direction :io 
			       ;; 	       :element-type '(unsigned-byte 8)
			       ;; 	       :if-exists :supersede))
			       (vec (make-array 10 :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t))
			       (stream (make-two-way-stream (flexi-streams:make-in-memory-input-stream vec)
							    (flexi-streams:make-in-memory-output-stream :element-type '(unsigne-byte 8))))
			       (continue t)
			       (receiver-state `(:init t :block-size ,blocksize))
			       (transmitter-state `(:init t :blocks ,(dtp-transmitter-prep data
											   :block-size blocksize))))
			  (loop ;rcv ack trans write rcv read
			     while continue
			     do (when continue
				  (setf receiver-state (dtp-receiver stream 
								     :state receiver-state))
				  (setf continue (getf receiver-state :continue))
				  (princ "rcv ack"))
			       
			     do (progn 
				  (setf transmitter-state (dtp-transmitter stream
									   :state transmitter-state))
				  (setf continue (getf transmitter-state :continue))
				  (princ "trans write"))
			     do (when continue
				  (setf receiver-state (dtp-receiver stream 
								     :state receiver-state))
				  (setf continue (getf receiver-state :continue))
				  (princ "rcv read")))
			  receiver-state)))

;; < Pure lisp >
(declaim (inline update-crc16-lisp))
(defun update-crc16-lisp (crc data)
  (declare (type (unsigned-byte 16) crc)
           (type (unsigned-byte  8) data)
           (optimize (speed 3) (safety 0) (debug 0)))
  (setf data (the (unsigned-byte 8) (ldb (byte 8 0) (logand crc #x9021))))
  (setf data (ash data 4))
  (the (unsigned-byte 16)
    (ldb (byte 16 0)
         (logxor (logior (the (unsigned-byte 16) (ash data 8))
                         (the (unsigned-byte  8) (ldb (byte 8 0) (ash crc -8))))
                 (the (unsigned-byte  8) (ldb (byte 8 0) (ash data -4)))
                 (the (unsigned-byte 16) (ash data  3))))))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(declaim (inline %crc16-lisp))
(defun %crc16-lisp (data)
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (optimize (speed 3) (safety 0) (debug 0)))
  (let ((crc #x0000))
    (declare (type (unsigned-byte 16) crc))
    (dotimes (i (length data) crc)
      (declare (type fixnum i))
      (setf crc (the (unsigned-byte 16)
                  (update-crc16-lisp crc (the (unsigned-byte 8)
                                            (aref data i))))))))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defun crc16-lisp (data)
  (let ((process-data (typecase data
                        ((simple-array (unsigned-byte 8) (*)) data)
                        (t (make-array (length data)
                                       :element-type '(unsigned-byte 8)
                                       :initial-contents data)))))
    (declare (type (simple-array (unsigned-byte 8) (*)) process-data))
    (%crc16-lisp process-data)))
;; </ Pure Lisp >
