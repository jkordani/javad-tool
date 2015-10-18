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
    (force-output socket)
    (javad-read socket)
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
      (loop for c = (read-char-no-hang is nil)
	 while c
	 while (member (char-code c) '(#x0d #x0a))
	 do (format t "erasing one newline")
	 finally (if (not (null c)) (progn (format t "putting back ~D" (char-code c))(unread-char c is))))
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

;;print /par/ref/pos/gps/geo /par/ref/arp/gps/geo
;; Default: {W84,N00d00m00.000000s,E00d00m00.000000s,+0.0000}
;; %01252%set,/par/ref/pos//geo,
;; %01253%set,/par/ref/arp//geo,

;; elevation mask
;; /par/lock/elm, -90,90
;; for file set,/par/out/elm/cur/file/a,10
;;          create,/log/filename:a
;;          em,/cur/file/a,def:30
;; first sets elevation mask for log capture
;; second makes a file with the current file name
;; third sets the output iteratoin to 30 seconds

;; base station params 
;; #set,/par/pos/elm,15                 # Set elevation mask
;; #set,/par/ref/avg/span,180
;; #set,/par/ref/avg/mode,on
;; #em,/dev/tcpo/c,/msg/rtcm3/{1004,1012,1006:10,1008:10}:1  # Enable RTCM3 messages at 1Hz

;; file list
;; list
;; /log:on
;; /cur/file/a|b&size  ;;prints name or sets filename to be currently active file a or b

(defun emit-rtcm (stream)
  (javad-generic-command stream "em,/dev/tcpo/c,/msg/rtcm3/{1004,1012,1006:10,1008:10}:1")
  (force-output stream)
  (javad-read stream))

(defun average-on (stream &key (duration 180) (reset nil))
  ;; don't forget to run average-off when you're done!!!
  (javad-generic-command stream (format nil "set,/par/ref/avg/span,~D" duration))
  (javad-generic-command stream "set,/par/ref/avg/mode,on")
  (if reset
      (javad-generic-command stream "set,/par/reset,y"))
  (force-output stream))

(defun average-query (stream)
  (javad-generic-command stream "print,/par/ref/avg/mode")
  (force-output stream)
  (javad-read stream))

(defun average-off (stream)
  (javad-generic-command stream "set,/par/ref/avg/mode,off")
  (force-output stream))

(defun get-pos-apc (stream)
  (javad-generic-command stream "print,/par/ref/pos/gps/geo")
  (javad-read stream))

(defun print-version (stream)
  (javad-generic-command stream "%FIRMWARE%print,rcv/ver")
  (javad-generic-command stream "%SERIAL%print,/par/rcv/sn")
  (javad-generic-command stream "%ID%print,/par/rcv/id")
  (force-output stream)
  (javad-read stream))

(defun set-network-ip (stream ip netmask &key (gw nil gw-supplied?) (reset nil))
  (javad-generic-command stream (format nil "set,/par/net/ip/addr,~A" ip))
  (javad-generic-command stream (format nil "set,/par/net/ip/mask,~A" netmask))
  (if gw-supplied?
      (javad-generic-command stream (format nil "set,/par/net/ip/gw,~A" gw)))
  (if reset
      (javad-generic-command stream "set,/par/reset,y")))

(defun get-network-ip (stream)
  (javad-generic-command stream "print,/par/net/ip/addr")
  (javad-generic-command stream "print,/par/net/ip/mask")
  (javad-generic-command stream "print,/par/net/ip/gw")
  (javad-read stream))

(defun javad-reset (stream)
  (javad-generic-command stream "set,/par/reset,y"))

(defun create-log (stream filename &key (interval 30) (elevation-mask-deg 15) (a-or-b? "a") (remove? nil))
  (if remove? (javad-generic-command stream (format nil "remove,/log/~A" filename)))
  (javad-generic-command stream (format nil "set,/par/out/elm/cur/file/~A,~D" a-or-b? elevation-mask-deg))
  (javad-generic-command stream (format nil "create,/log/~A:~A" filename a-or-b?))
  (javad-generic-command stream (format nil "em,/cur/file/~A,def:~D" a-or-b? interval)))

(defun list-log-names (stream)
  (javad-generic-command stream "print,/log:on")
  (javad-read stream))

(defun stop-log (stream a-or-b?)
  (javad-generic-command stream (format nil "dm,/cur/file/~A" a-or-b?)))

#+ccl
(defun download-file (stream remote-name &key (local-name nil local-name-supplied?))
  (if (not local-name-supplied?) (setf local-name remote-name))
  ;; first get target file size.
  (let* ((javad-message (progn (javad-generic-command stream (format nil "print,/log/~A&size" remote-name))
			       (javad-parse-message stream)))
	 (size (parse-integer
		(ccl::decode-string-from-octets (slot-value javad-message 'data))
		:junk-allowed t)))
    (javad-generic-command stream (format nil "print,/log/~A&content" remote-name))
    (with-open-file (o local-name
    		       :direction :output
    		       :element-type 'unsigned-byte
    		       :if-exists :supersede)
      (dotimes (i size)
    	(write-byte (read-byte stream nil) o)))))


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

(defun download-file-dtp (stream remote-file &key (blocksize 512) (timeout 10))
  (let* ((javad-message (progn (javad-generic-command stream (format nil "print,/log/~A&size" remote-file))
			       (javad-parse-message stream)))
	 (size (parse-integer
		(ccl::decode-string-from-octets (slot-value javad-message 'data))
		:junk-allowed t))
	 (state nil))

  ;;;;;CLEAR WHITESPACE!!!!!!
    
    (format t "blocks to get should be ~D~%" (ceiling size blocksize))
    (javad-generic-command stream (format nil "get,/log/~A:{~D,~D}" remote-file timeout blocksize))
    (setf state (dtp-receiver stream :blocksize blocksize))
    (dotimes (i (ceiling size blocksize))
      (setf state (dtp-receiver stream :blocksize blocksize :state state)))

    state))

(defun dtp-receiver (stream &key (state '(:init t :task ack)) (blocksize 512))
  (declare  (optimize (debug 3) (safety 3)))
  (force-output)
  (format t "~A blocksize:~A ~%" state blocksize)
  (force-output)
  (let ((type nil))
    (cond 
      ((getf state :init)
       (setf (getf state :init) nil)
       (format t "init, sending nack~%")
       (setf (getf state :task) 'rcv)
       (setf (getf state :blocks) nil)
       (setf (getf state :next-block) 0)
       (setf (getf state :continue) t)
       (write-byte #x15 stream) ;nack to init transfer
       (force-output stream))
     
      ((equal (getf state :task) 'ack)
       (format t "sending ack~%")
       (force-output stream)
       (write-byte #x06 stream)
       (force-output stream)
       (setf (getf state :task) 'rcv)
       (setf (getf state :continue) t)
       (incf (getf state :next-block))
       (force-output stream))
      
      ((equal (getf state :task) 'rcv)
       (format t "inner rcv~%")
       (setf (getf state :task) 'ack)
       (setf type (read-byte stream))
       (read-byte stream) ;; either block num or last block byte count
       (read-byte stream)
       (setf (getf state :blocks) (push
				   (list type
					 (let ((vector (make-array blocksize
								   :element-type '(unsigned-byte 8)
								   :fill-pointer 0)))
					   (dotimes (i blocksize)
					     (setf (aref vector i) (read-byte stream)))
					   vector))
				   (getf state :blocks)))
       ;;throw away checksum and end byte for now
       (read-byte stream)
       (read-byte stream)
       (read-byte stream)
       (if (= type #x02)
	   (setf (getf state :continue) t)
	   (setf (getf state :continue) nil))))
    state))

(defun dtp-transmitter (stream &key state)
  ;assumes blocks are loaded in state
  (let ((rcv-ack (read-byte stream))
	(block nil))
    (cond 
      ((and (getf state :init)
	    (equal rcv-ack #x15))
       (setf (getf state :init) nil)
       (setf (getf state :next-block) 0))
      (t (incf (getf state :next-block))))

    (setf block (nth (getf state :next-block) (getf state :blocks)))
    (write-byte (car block) stream)
    ;; (write-byte (cadr block) stream)
    ;; (write-byte (caddr block) stream)
    (ccl:stream-force-output stream)
    state))

(defun dtp-trans-receive (data &key (blocksize 512)) ;need to send ack then read ack then send block then read block, and... can't be in the same file...???
  (ccl:with-open-socket (trans-socket :local-port 8002
				      :connect :passive
				      :address-family :internet
				      :reuse-address t)
			(ccl:with-open-socket (recv-socket :remote-port 8002
							   :address-family :internet
							   :reuse-address t)
					      (let* (
						     ;; (stream (open "/tmp/pipe" :direction :io 
						     ;; 	       :element-type '(unsigned-byte 8)
						     ;; 	       :if-exists :supersede))
						     
						     (continue t)
						     (receiver-state `(:init t :block-size ,blocksize))
						     (transmitter-state `(:init t :blocks ,(dtp-transmitter-prep data
														 :block-size blocksize)))
						     (trans-stream (ccl:accept-connection trans-socket)))
						(loop ;rcv ack trans write rcv read
						   while continue
						   do (when continue
							(setf receiver-state (dtp-receiver recv-socket 
											   :state receiver-state))
							(setf continue (getf receiver-state :continue))
							(princ "rcv ack"))
						     
						   do (progn 
							(setf transmitter-state (dtp-transmitter trans-stream
												 :state transmitter-state))
							;; (setf continue (getf transmitter-state :continue))
							(princ "trans write"))
						   do (when continue
							(setf receiver-state (dtp-receiver recv-socket
											   :state receiver-state))
							(setf continue (getf receiver-state :continue))
							(princ "rcv read")))
						receiver-state))))
