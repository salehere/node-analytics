#node-analytics

node-analytics is an ExpressJS visitor analytic middleware.

## Installation

```sh
$ npm install --save node-analytics
```

## Prenuptials

Complete node-analytics functionality relies upon the following:

- **MongoDB**: a `mongod` instance must be running on the server for data storage
- a **MaxMind** GeoIP database for location data; the free GeoLite2 City database is [available here](http://dev.maxmind.com/geoip/geoip2/geolite2/)
- **WebSocket** for client behaviour data; ensure that your WebSocket port of choice is clear for action on your server *(defaults to 8080)*

## Basic usage

#### app.js

In its current iteration node-analytics will process every server request, including static files. To restrict it to page loads call the middleware **after** the `express.static` middleware.

```javascript
var express = require('express')
,   analytics = require('node-analytics')

var app = express();

// app middleware //
app.use(express.static(path.join(__dirname, 'public')));
app.use(analytics());   // beneath express.static
```

#### Client

The client script **node-analytics-client.js** must be included on the served webpage.

```html
<script type='text/javascript' src='/path/to/node-analytics-client.js'></script>
```

## User behaviour

On the client side, node-analytics logs *clicks*, *reaches*, and *reads* of elements, each assigned their own class:

Event | Logged when element | Element class | Note
--- | --- | --- | ---
`click` | clicked (e.g. link) | *na_click* | Emits for every click
`reach` | scrolled to | *na_reach* | Emits once per page load
`read` | paused at and, presumptively, read | *na_read* | Tallies time spent paused within element bounds

Events will be associated with an element's `id` property, or will otherwise be assigned an index.

```html
<section id="contact" class="na-read">      //id: contact
  
  <a href="mailto:me" class="na-click">     //id: reach_point_0
    Contact us
  </a>
  
  <span="fine_print" class="na-reach">      //id: read_section_0
    in exchange for your marbles
  </span>
  
</section>
```

## Options

node-analytics may be adapted by the following options:

#### app.js

Key | Description | Default
--- | --- | ---
`db_host` | MongoDB host | *localhost*
`db_port` | MongoDB port | 27017
`db_name` | MongoDB database name | *node_analytics_db*
`ws_port` | WebSocket port | 8080
`geo_ip` | Use GeoIP boolean  | `true`
`mmdb` | MaxMind DB path | */GeoLite2-City.mmdb*
`log` | Output log boolean | `true`
`log_pre` | Output log prefix | *node-analytics \|\|*
`error_log` | Error log boolean | `true`
`error_pre` | Error log prefix | *node-analytics ERROR \|\|*

Example use:

```javascript
  app.use(analytics({
      db_host:  "https://npmjs.com"
    , ws_port:  8079
  }));
```

#### Client

Key | Description | Default
--- | --- | ---
`ws_host` | Websocket host | *localhost*
`ws_port` | Websocket port | 8080
`click_class` | Click-log class | *na_click*
`reach_class` | Reach-log class | *na_reach*
`read_class` | Read-log class | *na_read*

Example use (in **node-analytics-client.js**):
```javascript
var na_obj = {
    ws_host:        'https://npmjs.com'
  , ws_port:        8079
  , click_class:    'na_click'    // default value
  , reach_class:    'reached_me'
  , read_class:     'na_read'     // default value
};
```
