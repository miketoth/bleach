# Just Sanitize 

Sanitize your HTML the easy way!

![bleach](http://i.imgur.com/9qSfd.png)

## install

    yarn add just-sanitize 

## test

    vows --spec test/*

## example

Basic:

````javascript

var js = require('just-sanitize');

var html = js.sanitize(aBunchOfHTML);

console.log(html);
````

Advanced:

````javascript

const js = require('just-sanitize');

const whitelist = [
  'a',
  'b',
  'i',
  'em',
  'strong'
]

const options = {
  mode: 'white',
  list: whitelist
}

const html = js.sanitize(aBunchOfHTML, options);

console.log(html);
````

## usage

### js.sanitize(html, options)

Runs HTML through sanitizer and returns sanitized HTML as string.

`options` may contain the following optional attributes:

*   `mode` may be set to `'white'` or `'black'`
*   `list` is an array containing tags to match against

`white`mode will remove all tags from `html`, excluding those in `list`

`black`mode will remove all tags found in `list` that are found in `html`

### js.analyze(html)

Will extract all tags from HTML and return an array of JSON objects. Example return:

````javascript
[
  {
    full: '<div id="post-119477">',
    name: 'div',
    attr: [
      "id": "post-119477"
    ]
  },
  ...
]
````

## disclaimer

This is not a port of the Python **bleach** library - in fact their implementations are very different.

## license

(The MIT License)

Copyright (c) 2011 Cam Pedersen <cam@onswipe.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
