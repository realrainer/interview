#!/bin/sh

cd `dirname $0`
npm install

cd `dirname $0`/static
bower install

go get github.com/gorilla/websocket && \
go get github.com/jinzhu/gorm && \
go get github.com/jinzhu/gorm/dialects/mysql && \
go get github.com/mqu/openldap && \
go get golang.org/x/net/xsrftoken && \
go get gopkg.in/gin-gonic/gin.v1

