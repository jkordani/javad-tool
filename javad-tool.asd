;;;; javad-tool.asd

(asdf:defsystem #:javad-tool
  :serial t
  :description "Describe javad-tool here"
  :author "Your Name <your.name@example.com>"
  :license "Specify license here"
  :depends-on (#:usocket #:ltk #:ie3fp #:cl-ppcre)
  :components ((:file "package")
               (:file "javad-tool")))

