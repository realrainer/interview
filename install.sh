#!/bin/sh

cd `dirname $0`
npm install

cd `dirname $0`/static
bower install
