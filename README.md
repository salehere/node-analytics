#node-analytics

[node-analytics](https://www.npmjs.com/package/node-analytics) is an ExpressJS visitor analytic middleware.

## Installation

```sh
$ npm install node-analytics
```

## Prerequisites

Complete node-analytics functionality relies upon the following:

- **MongoDB**: a `mongod` instance must be running on the server for data storage
- a **MaxMind** GeoIP database for location data; the free GeoLite2 City database is [available here](http://dev.maxmind.com/geoip/geoip2/geolite2/)
- an open **WebSocket** for client behaviour data collection; ensure port is open (default is 8080) or pass in server object
 
Though it will function without one, some, or all of the above.

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

The client script **node-analytics-client.js** must be included on the served webpage beneath the [socket.io](http://socket.io/) client script. Specify the client JS directory `client_dir` as an option and the file will be automatically copied, or disable this behaviour by `client_copy: false`.

```html
<script type='text/javascript' src="https://cdn.socket.io/socket.io-1.4.5.js"></script>
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
<section id="contact" class="na_read">      //id: contact
  
  <a href="mailto:me" class="na_click">     //id: reach_point_0
    Contact us
  </a>
  
  <span="fine_print" class="na_reach">      //id: read_section_0
    in exchange for your marbles
  </span>
  
</section>
```

## Options

node-analytics may be adapted by the following options:

#### app.js

Key | Description | Default
--- | --- | ---
`client_copy` | Copy **node-analytics-client.js** to client-side dir? | `true`
`client_dir` | Client-side JS directory | `'public/js'`
`db_host` | MongoDB host | `'localhost'`
`db_port` | MongoDB port | `27017`
`db_name` | MongoDB database name | `'node_analytics_db'`
`ws_port` | WebSocket port; disabled if `ws_server` is set | `8080`
`ws_server` | Express server object | `null`
`geo_ip` | Use GeoIP boolean  | `true`
`mmdb` | MaxMind DB path | `'GeoLite2-City.mmdb'`
`log` | Output log boolean | `true`
`log_pre` | Output log prefix | `'node-analytics ||'`
`error_log` | Error log boolean | `true`
`error_pre` | Error log prefix | `'node-analytics ERROR ||'`

Example use with WebSocket server instead of port (see necessary client edit below):

```javascript
var server = require('http').createServer(app);
server.listen(80);

app.use(analytics({
  ws_server:  server
}));
```

#### Client

Key | Description | Default
--- | --- | ---
`ws_host` | Websocket host | `location.hostname`
`ws_port` | Websocket port; must disable if using `ws_server` in **app.js** | `8080`
`click_class` | Click-log class | `'na_click'`
`reach_class` | Reach-log class | `'na_reach'`
`read_class` | Read-log class | `'na_read'`
`force_protocol` | Force `'http'` or `'https'` | null

Example use including server support (editing **node-analytics-client.js**):
```javascript
var na_obj = {
    ws_port:        `null`          // must be disabled if server object is being used
  , click_class:    'clicked_me'
  , reach_class:    'reached_me'
  , read_class:     'read_me'
};
```
