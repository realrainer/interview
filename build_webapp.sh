#!/bin/sh

cd `dirname $0`
./node_modules/vulcanize/bin/vulcanize ./static/bundle.src.html --out-html ./static/bundle.vulc.html \
    --strip-comments --inline-css --inline-scripts \
    --exclude ./static/bower_components/polymer/polymer.html \
    --exclude ./static/bower_components/polymer/polymer-mini.html \
    --exclude ./static/bower_components/polymer/polymer-micro.html \
    --strip-exclude ./static/bower_components/font-roboto/roboto.html

./node_modules/.bin/html-minifier ./static/bundle.vulc.html \
    --remove-empty-attributes \
    --collapse-whitespace \
    --conservative-collapse \
    --minify-js \
    --minify-css \
    --remove-comments \
    > ./static/bundle.html

rm ./static/bundle.vulc.html
