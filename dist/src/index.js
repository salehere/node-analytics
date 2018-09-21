'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.sessions = undefined;

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _mongoose = require('mongoose');

var _mongoose2 = _interopRequireDefault(_mongoose);

var _useragent = require('useragent');

var _useragent2 = _interopRequireDefault(_useragent);

var _maxmind = require('maxmind');

var _maxmind2 = _interopRequireDefault(_maxmind);

var _cookie = require('cookie');

var _cookie2 = _interopRequireDefault(_cookie);

var _async = require('async');

var _async2 = _interopRequireDefault(_async);

var _socket2 = require('socket.io');

var _socket3 = _interopRequireDefault(_socket2);

var _chalk = require('chalk');

var _chalk2 = _interopRequireDefault(_chalk);

var _cryptoJs = require('crypto-js');

var _cryptoJs2 = _interopRequireDefault(_cryptoJs);

var _onHeaders = require('on-headers');

var _onHeaders2 = _interopRequireDefault(_onHeaders);

var _onFinished = require('on-finished');

var _onFinished2 = _interopRequireDefault(_onFinished);

var _andraoLogger = require('andrao-logger');

var _andraoLogger2 = _interopRequireDefault(_andraoLogger);

var _ipware = require('ipware');

var _ipware2 = _interopRequireDefault(_ipware);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// installed
var getIpFn = (0, _ipware2.default)().get_ip;

// globals
/* eslint-disable
  prefer-destructuring,no-use-before-define,
  consistent-return,no-nested-ternary,no-param-reassign,
  no-shadow,eqeqeq,no-underscore-dangle,no-plusplus,
  no-mixed-operators,no-restricted-syntax,guard-for-in */

/*
 * https://github.com/andrao/node-analytics
 */

var db = void 0;

var geoLookup = void 0;
var io = false;
var log = (0, _andraoLogger2.default)('n-a');

// -------------------------------------------------------------

var requestSchema = _mongoose2.default.Schema({
  _id: { type: String, unique: true, index: true },
  host: String,
  date: { type: Date, default: Date.now },
  url: { type: String, index: true },
  query: [{ field: String, value: String }],
  ref: { type: String, index: true },
  referrer: String,
  method: String,
  time: Number,
  reaches: [String],
  pauses: [{
    _id: false,
    id: String,
    time: Number
  }],
  clicks: [String]
});

var sessionSchema = _mongoose2.default.Schema({
  user: { type: String, index: true },
  name: { type: String, index: true },
  date: { type: Date, default: Date.now },
  last: { type: Date, default: Date.now },
  ip: String,
  is_bot: { type: Boolean, default: true },
  geo: {
    _id: false,
    city: { type: String, index: true },
    state: { type: String, index: true },
    country: { type: String, index: true },
    continent: { type: String, index: true },
    time_zone: { type: String, index: true }
  },
  system: {
    os: {
      _id: false,
      name: String,
      version: String
    },
    browser: {
      _id: false,
      name: String,
      version: String
    }
  },
  time: Number,
  resolution: {
    _id: false,
    width: Number,
    height: Number
  },
  reqs: [requestSchema],
  state: String,
  flash_data: _mongoose2.default.Schema.Types.Mixed
});
var Session = _mongoose2.default.model('Session', sessionSchema);

exports.default = analytics;
exports.sessions = sessions;


var opts = {
  db_host: '127.0.0.1',
  db_port: 27017,
  db_name: 'node_analytics_db',
  ws_port: 8080,
  ws_server: false,
  s_io: false,
  geo_ip: true,
  mmdb: 'GeoLite2-City.mmdb',
  log: true,
  log_all: false,
  error_log: true,
  secure: true,
  secret: 'changeMe',
  log_opts: {
    pre: 'n-a'
  },
  mongoose_params: {
    useNewUrlParser: true,
    autoReconnect: true,
    keepAlive: true,
    keepAliveInitialDelay: 120,
    socketTimeoutMS: 30000,
    connectTimeoutMS: 30000,
    poolSize: 50,
    reconnectTries: 500,
    reconnectInterval: 3000
  }
};

log('active: wait for MongoDB, GeoIP, & WebSocket');
log("don't forget to copy", _chalk2.default.red('node-analytics-client.js'), 'to public directory');

function mongoDB(cb) {
  // Connect to MongoDB
  var dbUrl = 'mongodb://' + opts.db_host + ':' + opts.db_port + '/' + opts.db_name;

  db = _mongoose2.default.connection;

  var dbConnect = setTimeout(function () {
    log(_chalk2.default.cyan('mongoose.connect'));
    _mongoose2.default.connect(dbUrl, opts.mongoose_params);
  }, 500);

  db.on('connecting', function () {
    log(_chalk2.default.yellow('MongoDB connecting'));
  });
  db.on('error', function (err) {
    log.error(_chalk2.default.red('MongoDB error'), err);
  });
  db.on('connected', function () {
    log(_chalk2.default.yellow('MongoDB connected:'), 'Wait for open.');

    if (dbConnect) {
      clearTimeout(dbConnect);
    }
  });
  db.once('open', function () {
    log(_chalk2.default.green('MongoDB connection open'));
    cb(null);
  });
  db.on('reconnected', function () {
    log(_chalk2.default.green('MongoDB reconnected.'));
  });
  db.on('disconnected', function () {
    log.error(_chalk2.default.red('MongoDB disconnected!'), 'Attempting reconnect.');
  });
}

function geoDB(cb) {
  // Check for mmdb
  if (opts.geo_ip) {
    _maxmind2.default.open(opts.mmdb, function (err, mmdb) {
      if (err) {
        log.error('GeoIP DB open error', opts.mmdb, err);
        return cb(true);
      }

      geoLookup = mmdb;
      log('GeoIP DB loaded successfully');
      cb(null);
    });
  } else {
    log('GeoIP disabled');
    cb(null);
  }
}

function socketInit(cb) {
  io = opts.s_io ? opts.s_io : opts.ws_server ? _socket3.default.listen(opts.ws_server) : (0, _socket3.default)(opts.ws_port);

  io.of('/node-analytics').use(function (_ref, next) {
    var handshake = _ref.handshake;

    if (handshake.headers.cookie) {
      var cookies = getCookies(handshake.headers.cookie);
      if (cookies && cookies.na_session) {
        next();
      }
    } else {
      log.error('Socket authentication error; no session cookie');
    }
  }).on('connection', socketConnection);

  log('Websocket server established');

  cb(null);
}

// =====================

function socketConnection(socket) {
  var cookies = getCookies(socket.handshake.headers.cookie);

  socket.session_start = Date.now();
  socket.blurred = 0;
  socket.blurring = Date.now();
  socket.req_id = cookies.na_req;
  socket.session_id = cookies.na_session;

  // Get session
  if (socket.session_id) {
    Session.findById(socket.session_id, function (err, session) {
      if (err) {
        return log.error('Session find error :: id[socket]', this.session_id, err);
      }
      if (!session) {
        return log.error('Session not found :: id[socket]', this.session_id);
      }

      var socket = this;

      // set regional session and request
      socket.session = session;
      if (socket.req_id) {
        for (var i = session.reqs.length - 1; i >= 0; i--) {
          if (session.reqs[i]._id.toString() == socket.req_id) {
            socket.req = session.reqs[i];
            break;
          }
        }
      }

      // log and initiate socket sensitivity
      if (!socket.req) {
        log.error('socket connected; request not found');
      } else if (opts.log_all) {
        log.session(session, 'socket connected; request:', socket.req._id);
      }

      socketResponse(socket);
    }.bind(socket));
  }

  // =============

  function socketResponse(socket) {
    // session updates from the client

    // Trivial not-bot check: socket connects;
    //   Could / should be improved to having done action on page

    if (socket.session.is_bot) {
      Update.session(socket.session, { $set: { is_bot: false } });
    }

    if (!socket.session.resolution) {
      socket.on('resolution', _socket.resolution.bind(socket));
    }

    // request updates
    socket.on('click', _socket.click.bind(socket));
    socket.on('reach', _socket.reach.bind(socket));
    socket.on('pause', _socket.pause.bind(socket));

    // session timer
    socket.on('blur', _socket.blur.bind(socket));
    socket.on('focus', _socket.focus.bind(socket));

    // Disconnection
    socket.on('disconnect', _socket.disconnect.bind(socket));
  }
}

var _socket = {
  click: function click(id) {
    if (this.req) {
      Update.request(this, { $push: { clicks: id } });
    }

    if (opts.log) {
      log.session(this.session, _chalk2.default.green('click'), '@', _chalk2.default.cyan(id));
    }
  },
  reach: function reach(id) {
    if (this.req) {
      Update.request(this, { $push: { reaches: id } });
    }

    if (opts.log) {
      log.session(this.session, _chalk2.default.yellow('reach'), '@', _chalk2.default.cyan(id));
    }
  },
  pause: function pause(params) {
    if (this.req) {
      Update.request(this, { $push: { pauses: params } });
    }

    if (opts.log) {
      log.session(this.session, _chalk2.default.magenta('pause'), 'for ' + params.time + 's @', _chalk2.default.cyan(params.id));
    }
  },
  blur: function blur() {
    this.blurring = Date.now();
  },
  focus: function focus() {
    this.blurred += Date.now() - this.blurring;
  },
  resolution: function resolution(params) {
    Update.session(this.session, { $set: { resolution: params } });
  },
  disconnect: function disconnect() {
    if (!this || !this.req) {
      return;
    }

    // request time, sans blurred time
    var t = (Date.now() - this.session_start - this.blurred) / 1000;

    // total session time; begin with this request
    var sessionT = t;
    for (var i = 0; i < this.session.reqs.length; i++) {
      sessionT += this.session.reqs[i].time;
    }

    // update request & session
    this.req.time = t;
    if (this.req) {
      Update.request(this, { $set: { time: t } });
    }

    Update.session(this.session, { $set: { session_time: sessionT } });

    if (opts.log) {
      log.session(this.session, _chalk2.default.red(t));
    }
  }
};

// ===============

var SESSION_FIELDS = '_id user name date last flash_data';

function analytics(optsIn) {
  for (var k in optsIn) {
    opts[k] = optsIn[k];
  }

  if (!opts.log_opts.pre) {
    opts.log_opts.pre = 'n-a';
  }

  log = (0, _andraoLogger2.default)(opts.log_opts);

  _async2.default.parallelLimit([mongoDB, socketInit, geoDB], 2, function (err) {
    if (err) {
      return log.error('start-up interrupted');
    }

    log(_chalk2.default.green('NODE ANALYTICS READY'));
  });

  // HTTP request:
  return function (req, res, next) {
    // Skip cases
    if (req.url.indexOf('/socket.io/?EIO=') == 0) {
      return next();
    }
    _async2.default.waterfall([function (cb) {
      getSession(req, res, cb);
    }, setCookies, sessionData, newRequest, logRequest, sessionSave, sessionFlash], function (err, session) {
      if (err) {
        log.error(err);
        next();
        return false;
      }
      req.node_analytics = session;
      next();
    });
  };
}

// =====================

// populate var session; returns boolean on whether newly formed
function getSession(req, res, cb) {
  var now = new Date();
  var cookies = getCookies(req.headers.cookie);

  // cookies.na_session  :: session._id
  // cookies.na_user     :: session.user

  // Establish session: new/old session? new/old user?
  if (cookies.na_session) {
    if (opts.log_all) {
      log('Session cookie found:', cookies.na_session);
    }

    Session.findById(cookies.na_session, SESSION_FIELDS).lean().exec(function (err, session) {
      var _this = this;

      if (err) {
        log.error('getSession error', err);
        return cb(err);
      }

      if (!session) {
        log.error('Session not found :: id[cookie]:', this.cookies.na_session);

        // send to check if user instead
        if (cookies.na_user) {
          userSession();
        } else {
          newSession();
        }
      } else {
        Update.session(session, {
          $set: {
            last: Date.now()
          }
        }, function (err, session) {
          if (err) {
            log.error('establish session / update error');
            return cb(true);
          }

          session.continued = true;
          cb(err, _this.req, _this.res, session);
        });
      }
    }.bind({
      cookies: cookies,
      req: req,
      res: res
    }));
  } else if (cookies.na_user) {
    userSession();
  } else {
    newSession();
  }

  // ====================

  function userSession() {
    // OLD USER, NEW SESSION

    cb(null, req, res, new Session({
      user: cookies.na_user,
      new_session: true
    }).toObject({ virtuals: true }));

    if (opts.log_all) {
      log.timer('getSession 1', now);
    }
  }

  function newSession() {
    // NEW USER, NEW SESSION
    // Initiate session to get _id
    var session = new Session();
    session.user = session._id.toString();
    session.new_user = true;

    session = session.toObject({ virtuals: true });

    cb(null, req, res, session);

    if (opts.log_all) {
      log.timer('getSession 2', now);
    }
  }
}

// set cookies
function setCookies(req, res, session, cb) {
  var now = new Date();

  // Set cookies
  res.cookie('na_session', AES.encrypt(session._id.toString()), {
    maxAge: 1000 * 60 * 15, // 15 mins
    httpOnly: true,
    secure: opts.secure
  });
  res.cookie('na_user', AES.encrypt(session.user), {
    maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
    httpOnly: true,
    secure: opts.secure
  });

  cb(null, req, res, session);

  if (opts.log_all) {
    log.timer('setCookies', now);
  }
}

// append session data
function sessionData(req, res, session, cb) {
  var now = new Date();

  if (session.continued) {
    return cb(null, req, res, session);
  }

  _async2.default.parallelLimit([getIp, getLocation, getSystem], 2, function (err) {
    cb(err, this.req, this.res, this.session);

    if (opts.log_all) {
      log.timer('sessionData', now);
    }
  }.bind({
    req: req,
    res: res,
    session: session
  }));

  // ======================

  // .ip
  function getIp(cb) {
    session.ip = getIpFn(req).clientIp;
    cb(null);
  }

  // .geo :: .city, .state, .country
  function getLocation(cb) {
    if (!geoLookup) {
      return cb(null);
    }

    var loc = geoLookup.get(session.ip);

    if (!session.geo) {
      session.geo = {};
    }

    if (loc) {
      try {
        if (loc.city) {
          session.geo.city = loc.city.names.en;
        }
        if (loc.subdivisions) {
          session.geo.state = loc.subdivisions[0].iso_code;
        }
        if (loc.country) {
          session.geo.country = loc.country.iso_code;
        }
        if (loc.continent) {
          session.geo.continent = loc.continent.code;
        }
        if (loc.location) {
          session.geo.time_zone = loc.location.time_zone;
        }
      } catch (e) {
        log.error('geoIP error:', e);
      }
    }

    cb(null);
  }

  // .system :: .os{, .broswer{ .name, .version
  function getSystem(cb) {
    var agent = _useragent2.default.parse(req.headers['user-agent']);
    var os = agent.os;

    if (!session.system) {
      session.system = {};
    }

    if (!session.system.browser) {
      session.system.browser = {};
    }
    if (!session.system.os) {
      session.system.os = {};
    }

    session.system.browser.name = agent.family;
    session.system.browser.version = agent.major + '.' + agent.minor + '.' + agent.patch;

    session.system.os.name = os.family;
    session.system.os.version = os.major + '.' + os.minor + '.' + os.patch;

    cb(null);
  }
}

// return new request document, create req cookie
function newRequest(req, res, session, cb) {
  var now = new Date();

  var request = {
    _id: 'r' + _crypto2.default.randomBytes(16).toString('hex') + Date.now(),
    host: req.hostname,
    url: req.url,
    method: req.method,
    referrer: req.get('Referrer') || req.get('Referer')
  };

  // populate request query
  for (var field in req.query) {
    if (field === 'ref') {
      request.ref = req.query[field];
    } else {
      if (!request.query) {
        request.query = [];
      }

      request.query.push({
        field: field,
        value: req.query[field]
      });
    }
  }

  // add request cookie for communication/association with socket
  res.cookie('na_req', AES.encrypt(request._id), {
    maxAge: 1000 * 60 * 15, // 15 mins
    httpOnly: true,
    secure: opts.secure
  });

  // return request object: will be added at sessionSave();
  cb(null, req, res, session, request);

  if (opts.log_all) {
    log.timer('newRequest', now);
  }
}

// log request
function logRequest(req, res, session, request, cb) {
  var now = new Date();

  if (opts.log) {
    (0, _onHeaders2.default)(res, logStart.bind(res));
    (0, _onFinished2.default)(res, reqLog.bind({
      req: request,
      ses: session
    }));
  }

  cb(null, session, request);

  if (opts.log_all) {
    log.timer('logRequest', now);
  }

  // / ==============

  function logStart() {
    this._log_start = process.hrtime();
  }
  function reqLog() {
    var _log;

    var request = this.req;
    var session = this.ses;

    // Status colour
    var sc = res.statusCode < 400 ? 'green' : 'red';

    // Res time
    var ms = nanoTime(res._log_start);

    // Referrer
    var ref = request.referrer;
    if (ref) {
      ref = ref.replace('http://', '');
      ref = ref.replace('https://', '');
    }

    // Args
    var args = [session, '|', _chalk2.default.magenta(request.url), '|', request.method, _chalk2.default[sc](res.statusCode), ': ' + ms + ' ms'];

    if (session && session.system) {
      args.push('|');

      if (session.system.browser) {
        args.push(_chalk2.default.grey(session.system.browser.name));
        args.push(_chalk2.default.grey(session.system.browser.version));
      }
      if (session.system.os) {
        args.push(_chalk2.default.grey(session.system.os.name));
        args.push(_chalk2.default.grey(session.system.os.version));
      }
    }

    if (ref) {
      args.push('|', _chalk2.default.grey('from ' + ref));
    }

    // Apply
    (_log = log).session.apply(_log, args);

    // ===

    function nanoTime(start) {
      var t = conv(process.hrtime()) - conv(start); // ns
      t = Math.round(t / 1000); // µs
      return t / 1000; // ms [3 dec]

      // ====

      function conv(t) {
        if (!t || typeof t[0] === 'undefined') {
          return 0;
        }

        return t[0] * 1e9 + t[1];
      }
    }
  }
}

// save / update session to DB & proceed to socket
function sessionSave(session, request, cb) {
  var now = new Date();

  if (!session.continued) {
    session.reqs = [request];

    Update.session(session, { $set: session }, function (err, session) {
      if (err) {
        return cb('db session save error');
      }

      if (opts.log_all) {
        log.session(session, 'session active [ new ]');
      }

      cb(null, session);

      if (opts.log_all) {
        log.timer('sessionSave 1', now);
      }
    });
  } else {
    // an old session: all that needs be updated is request
    Update.session(session, { $push: { reqs: request } }, function (err, session) {
      if (err) {
        log.error('db session update error');
        return cb(true);
      }

      if (opts.log_all) {
        log.session(session, 'session active [ updated ]');
      }

      cb(null, session);

      if (opts.log_all) {
        log.timer('sessionSave 2', now);
      }
    });
  }
}

function sessionFlash(session, cb) {
  var now = new Date();

  // SESSION OBJECT FUNCTIONS
  session.identify = Identify.bind(session);
  session.flash = Flash.bind(session);
  session.save = Update.session_save.bind(session);

  // Expire and clear flash data
  for (var k in session.flash_data) {
    if (session.flash_data[k].endurance !== 'indefinite' && (!session.flash_data[k].endurance || !(session.flash_data[k].endurance - 1))) {
      delete session.flash_data[k];
    } else if (session.flash_data[k].endurance !== 'indefinite') {
      session.flash_data[k].endurance--;
    }
  }

  Update.session(session, {
    $set: {
      flash_data: session.flash_data
    }
  }, function (err) {
    if (err) {
      log.error('sessionFlash update error', err);
    }

    cb(null, this);

    if (opts.log_all) {
      log.timer('sessionFlash', now);
    }
  }.bind(session));
}

// =====================

function Identify(name) {
  Update.session(this, { $set: { name: name } }, function (err) {
    if (err) {
      log.error('session.associate: name save error', err);
    }
  });
}

function Flash(field, value, endurance, cb) {
  // Return saved field value
  if (typeof value === 'undefined') {
    if (!this.flash_data || !this.flash_data[field]) {
      return null;
    }

    return this.flash_data[field].val;
  }

  // Save new field value for next session

  // Endurance represents number of page loads that this variable will last for
  //  (Helpful in redirect situations)
  if (typeof endurance === 'function') {
    cb = endurance;
    endurance = 1;
  } else if (!endurance) {
    endurance = 1;
  }

  if (!this.flash_data) {
    this.flash_data = {};
  }

  this.flash_data[field] = {
    val: value,
    endurance: endurance
  };
  Update.session(this, { $set: { flash_data: this.flash_data } }, function (err) {
    if (err) {
      log.error('flash data save error', err);
    }
    if (cb) {
      cb(err);
    }
  });
}

// =====================

var Update = {
  session_save: function session_save(cb) {
    var session = this;
    Update.session(session, {
      $set: session
    }, cb);
  },
  session: function session(_session, upd, cb) {
    var keys = Update._keys(upd);

    Session.findByIdAndUpdate(_session._id, upd, {
      new: true,
      fields: SESSION_FIELDS,
      upsert: true
    }).lean().exec(function (err, doc) {
      if (err) {
        log.error('Update.session error [', this, ']', err);
      } else if (!doc) {
        log.error('Update.session no session found!', _session);
      } else if (doc && opts.log_all) {
        log.session(doc, 'Update.session success [', this, ']');
      }

      if (cb) {
        cb(err, doc);
      }
    }.bind(keys));
  },
  request: function request(socket, updIn, cb) {
    var upd = {};

    for (var k in updIn) {
      // $push: { clicks: id }
      // -->
      // $push: { reqs.$.clicks: id }

      if (!upd[k]) {
        upd[k] = {};
      }

      for (var k2 in updIn[k]) {
        var reqKey = 'reqs.$.' + k2;
        upd[k][reqKey] = updIn[k][k2];
      }
    }

    var keys = Update._keys(upd);

    Session.update({
      _id: socket.session._id,
      'reqs._id': socket.req._id
    }, upd, function (err, _ref2) {
      var n = _ref2.n;

      var socket = this.socket;

      if (err) {
        log.error('Update.request error [', this.keys, ']', socket.session._id, socket.req._id, err);
      } else if (n < 1) {
        log.error('Update.request not found!', socket.session._id, socket.req._id);
      } else if (opts.log_all) {
        log.session(socket.session, 'Update.request success [', this.keys, ']');
      }

      if (cb) {
        return cb(err);
      }
    }.bind({
      socket: socket,
      keys: keys
    }));
  },
  _keys: function _keys(params) {
    var keys = [];

    for (var k in params) {
      for (var k2 in params[k]) {
        keys.push(k2);
      }
    }

    return keys;
  }
};

// =====================

function getCookies(src) {
  var cookies = _cookie2.default.parse(src || '');
  for (var k in cookies) {
    if (k.indexOf('na_') === 0) {
      try {
        cookies[k] = AES.decrypt(cookies[k]);
      } catch (err) {
        log.error('getCookies error', err);
        delete cookies[k];
      }
    }
  }

  return cookies;
}

var AES = {
  encrypt: function encrypt(value) {
    return _cryptoJs2.default.AES.encrypt(value, opts.secret).toString();
  },
  decrypt: function decrypt(encrypted) {
    return _cryptoJs2.default.AES.decrypt(encrypted, opts.secret).toString(_cryptoJs2.default.enc.Utf8);
  }
};

// =====================

function sessions(options, cb) {
  if (!cb) {
    cb = options;
    options = { is_bot: false };
  }

  var n = 32;

  Session.find(options).sort({ date: 'desc' }).limit(n).exec(function (err, results) {
    if (err) {
      log.error('Sessions query error:', err);
    }

    cb(err, results);
  });
}
//# sourceMappingURL=index.js.map