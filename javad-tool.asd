;;;; javad-tool.asd

(asdf:defsystem #:javad-tool
  :serial t
  :description "Describe javad-tool here"
  :author "Your Name <your.name@example.com>"
  :license "Specify license here"
  :depends-on (#:ie3fp #:cl-ppcre #:plokami #:flexi-streams)
  :components ((:file "package")
               (:file "javad-tool")))

