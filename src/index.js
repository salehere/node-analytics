/* eslint-disable
  prefer-destructuring,no-use-before-define,
  consistent-return,no-nested-ternary,no-param-reassign,
  no-shadow,eqeqeq,no-underscore-dangle,no-plusplus,
  no-mixed-operators,no-restricted-syntax,guard-for-in */

/*
 * https://github.com/andrao/node-analytics
 */

import crypto from 'crypto';
import mongoose from 'mongoose';
import useragent from 'useragent';
import maxmind from 'maxmind';
import cookie from 'cookie';
import async from 'async';
import sio from 'socket.io';
import chalk from 'chalk';
import CryptoJS from 'crypto-js';
import onHeaders from 'on-headers';
import onFinished from 'on-finished';
import logger from 'andrao-logger';
import ipware from 'ipware';

// installed
const getIpFn = ipware().get_ip;

// globals
let db;

let geoLookup;
let io = false;
let log = logger('n-a');

// -------------------------------------------------------------

const requestSchema = mongoose.Schema({
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
  pauses: [
    {
      _id: false,
      id: String,
      time: Number,
    },
  ],
  clicks: [String],
});

const sessionSchema = mongoose.Schema({
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
    time_zone: { type: String, index: true },
  },
  system: {
    os: {
      _id: false,
      name: String,
      version: String,
    },
    browser: {
      _id: false,
      name: String,
      version: String,
    },
  },
  time: Number,
  resolution: {
    _id: false,
    width: Number,
    height: Number,
  },
  reqs: [requestSchema],
  state: String,
  flash_data: mongoose.Schema.Types.Mixed,
});
const Session = mongoose.model('Session', sessionSchema);

export default analytics;
export { sessions };

const opts = {
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
    pre: 'n-a',
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
    reconnectInterval: 3000,
  },
};

log('active: wait for MongoDB, GeoIP, & WebSocket');

function mongoDB(cb) {
  // Connect to MongoDB
  const dbUrl = `mongodb://${opts.db_host}:${opts.db_port}/${opts.db_name}`;

  db = mongoose.connection;

  const dbConnect = setTimeout(() => {
    log(chalk.cyan('mongoose.connect'));
    mongoose.connect(
      dbUrl,
      opts.mongoose_params,
    );
  }, 500);

  db.on('connecting', () => {
    log(chalk.yellow('MongoDB connecting'));
  });
  db.on('error', (err) => {
    log.error(chalk.red('MongoDB error'), err);
  });
  db.on('connected', () => {
    log(chalk.yellow('MongoDB connected:'), 'Wait for open.');

    if (dbConnect) {
      clearTimeout(dbConnect);
    }
  });
  db.once('open', () => {
    log(chalk.green('MongoDB connection open'));
    cb(null);
  });
  db.on('reconnected', () => {
    log(chalk.green('MongoDB reconnected.'));
  });
  db.on('disconnected', () => {
    log.error(chalk.red('MongoDB disconnected!'), 'Attempting reconnect.');
  });
}

function geoDB(cb) {
  // Check for mmdb
  if (opts.geo_ip) {
    maxmind.open(opts.mmdb, (err, mmdb) => {
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
  io = opts.s_io ? opts.s_io : opts.ws_server ? sio.listen(opts.ws_server) : sio(opts.ws_port);

  io.of('/node-analytics')
    .use(({ handshake }, next) => {
      if (handshake.headers.cookie) {
        const cookies = getCookies(handshake.headers.cookie);
        if (cookies && cookies.na_session) {
          next();
        }
      } else {
        log.error('Socket authentication error; no session cookie');
      }
    })
    .on('connection', socketConnection);

  log('Websocket server established');

  cb(null);
}

// =====================

function socketConnection(socket) {
  const cookies = getCookies(socket.handshake.headers.cookie);

  socket.session_start = Date.now();
  socket.blurred = 0;
  socket.blurring = Date.now();
  socket.req_id = cookies.na_req;
  socket.session_id = cookies.na_session;

  // Get session
  if (socket.session_id) {
    Session.findById(
      socket.session_id,
      function (err, session) {
        if (err) {
          return log.error('Session find error :: id[socket]', this.session_id, err);
        }
        if (!session) {
          return log.error('Session not found :: id[socket]', this.session_id);
        }

        const socket = this;

        // set regional session and request
        socket.session = session;
        if (socket.req_id) {
          for (let i = session.reqs.length - 1; i >= 0; i--) {
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
      }.bind(socket),
    );
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

const _socket = {
  click(id) {
    if (this.req) {
      Update.request(this, { $push: { clicks: id } });
    }

    if (opts.log) {
      log.session(this.session, chalk.green('click'), '@', chalk.cyan(id));
    }
  },
  reach(id) {
    if (this.req) {
      Update.request(this, { $push: { reaches: id } });
    }

    if (opts.log) {
      log.session(this.session, chalk.yellow('reach'), '@', chalk.cyan(id));
    }
  },
  pause(params) {
    if (this.req) {
      Update.request(this, { $push: { pauses: params } });
    }

    if (opts.log) {
      log.session(
        this.session,
        chalk.magenta('pause'),
        `for ${params.time}s @`,
        chalk.cyan(params.id),
      );
    }
  },

  blur() {
    this.blurring = Date.now();
  },

  focus() {
    this.blurred += Date.now() - this.blurring;
  },

  resolution(params) {
    Update.session(this.session, { $set: { resolution: params } });
  },

  disconnect() {
    if (!this || !this.req) {
      return;
    }

    // request time, sans blurred time
    const t = (Date.now() - this.session_start - this.blurred) / 1000;

    // total session time; begin with this request
    let sessionT = t;
    for (let i = 0; i < this.session.reqs.length; i++) {
      sessionT += this.session.reqs[i].time;
    }

    // update request & session
    this.req.time = t;
    if (this.req) {
      Update.request(this, { $set: { time: t } });
    }

    Update.session(this.session, { $set: { session_time: sessionT } });

    if (opts.log) {
      log.session(this.session, chalk.red(t));
    }
  },
};

// ===============

const SESSION_FIELDS = '_id user name date last flash_data';

function analytics(optsIn) {
  for (const k in optsIn) {
    opts[k] = optsIn[k];
  }

  if (!opts.log_opts.pre) {
    opts.log_opts.pre = 'n-a';
  }

  log = logger(opts.log_opts);

  async.parallelLimit([mongoDB, socketInit, geoDB], 2, (err) => {
    if (err) {
      return log.error('start-up interrupted');
    }

    log(chalk.green('NODE ANALYTICS READY'));
  });

  // HTTP request:
  return (req, res, next) => {
    // Skip cases
    if (req.url.indexOf('/socket.io/?EIO=') == 0) {
      return next();
    }
    async.waterfall(
      [
        (cb) => {
          getSession(req, res, cb);
        },
        setCookies,
        sessionData,
        newRequest,
        logRequest,
        sessionSave,
        sessionFlash,
      ],
      (err, session) => {
        if (err) {
          log.error(err);
          next();
          return false;
        }
        req.node_analytics = session;
        next();
      },
    );
  };
}

// =====================

// populate var session; returns boolean on whether newly formed
function getSession(req, res, cb) {
  const now = new Date();
  const cookies = getCookies(req.headers.cookie);

  // cookies.na_session  :: session._id
  // cookies.na_user     :: session.user

  // Establish session: new/old session? new/old user?
  if (cookies.na_session) {
    if (opts.log_all) {
      log('Session cookie found:', cookies.na_session);
    }

    Session.findById(cookies.na_session, SESSION_FIELDS)
      .lean()
      .exec(function (err, session) {
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
          Update.session(
            session,
            {
              $set: {
                last: Date.now(),
              },
            },
            (err, session) => {
              if (err) {
                log.error('establish session / update error');
                return cb(true);
              }

              session.continued = true;
              cb(err, this.req, this.res, session);
            },
          );
        }
      }.bind({
        cookies,
        req,
        res,
      }));
  } else if (cookies.na_user) {
    userSession();
  } else {
    newSession();
  }

  // ====================

  function userSession() {
    // OLD USER, NEW SESSION

    cb(
      null,
      req,
      res,
      new Session({
        user: cookies.na_user,
        new_session: true,
      }).toObject({ virtuals: true }),
    );

    if (opts.log_all) {
      log.timer('getSession 1', now);
    }
  }

  function newSession() {
    // NEW USER, NEW SESSION
    // Initiate session to get _id
    let session = new Session();
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
  const now = new Date();

  // Set cookies
  res.cookie('na_session', AES.encrypt(session._id.toString()), {
    maxAge: 1000 * 60 * 15, // 15 mins
    httpOnly: true,
    secure: opts.secure,
  });

  res.cookie('na_user', AES.encrypt(session.user), {
    maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
    httpOnly: true,
    secure: opts.secure,
  });

  cb(null, req, res, session);

  if (opts.log_all) {
    log.timer('setCookies', now);
  }
}

// append session data
function sessionData(req, res, session, cb) {
  const now = new Date();

  if (session.continued) {
    return cb(null, req, res, session);
  }

  async.parallelLimit(
    [getIp, getLocation, getSystem],
    2,
    function (err) {
      cb(err, this.req, this.res, this.session);

      if (opts.log_all) {
        log.timer('sessionData', now);
      }
    }.bind({
      req,
      res,
      session,
    }),
  );

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

    const loc = geoLookup.get(session.ip);

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
    const agent = useragent.parse(req.headers['user-agent']);
    const os = agent.os;

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
    session.system.browser.version = `${agent.major}.${agent.minor}.${agent.patch}`;

    session.system.os.name = os.family;
    session.system.os.version = `${os.major}.${os.minor}.${os.patch}`;

    cb(null);
  }
}

// return new request document, create req cookie
function newRequest(req, res, session, cb) {
  const now = new Date();

  const request = {
    _id: `r${crypto.randomBytes(16).toString('hex')}${Date.now()}`,
    host: req.hostname,
    url: req.url,
    method: req.method,
    referrer: req.get('Referrer') || req.get('Referer'),
  };

  // populate request query
  for (const field in req.query) {
    if (field === 'ref') {
      request.ref = req.query[field];
    } else {
      if (!request.query) {
        request.query = [];
      }

      request.query.push({
        field,
        value: req.query[field],
      });
    }
  }

  // add request cookie for communication/association with socket
  res.cookie('na_req', AES.encrypt(request._id), {
    maxAge: 1000 * 60 * 15, // 15 mins
    httpOnly: true,
    secure: opts.secure,
  });

  // return request object: will be added at sessionSave();
  cb(null, req, res, session, request);

  if (opts.log_all) {
    log.timer('newRequest', now);
  }
}

// log request
function logRequest(req, res, session, request, cb) {
  const now = new Date();

  if (opts.log) {
    onHeaders(res, logStart.bind(res));
    onFinished(
      res,
      reqLog.bind({
        req: request,
        ses: session,
      }),
    );
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
    const request = this.req;
    const session = this.ses;

    // Status colour
    const sc = res.statusCode < 400 ? 'green' : 'red';

    // Res time
    const ms = nanoTime(res._log_start);

    // Referrer
    let ref = request.referrer;
    if (ref) {
      ref = ref.replace('http://', '');
      ref = ref.replace('https://', '');
    }

    // Args
    const args = [
      session,
      '|',
      chalk.magenta(request.url),
      '|',
      request.method,
      chalk[sc](res.statusCode),
      `: ${ms} ms`,
    ];

    if (session && session.system) {
      args.push('|');

      if (session.system.browser) {
        args.push(chalk.grey(session.system.browser.name));
        args.push(chalk.grey(session.system.browser.version));
      }
      if (session.system.os) {
        args.push(chalk.grey(session.system.os.name));
        args.push(chalk.grey(session.system.os.version));
      }
    }

    if (ref) {
      args.push('|', chalk.grey(`from ${ref}`));
    }

    // Apply
    log.session(...args);

    // ===

    function nanoTime(start) {
      let t = conv(process.hrtime()) - conv(start); // ns
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
  const now = new Date();

  if (!session.continued) {
    session.reqs = [request];

    Update.session(session, { $set: session }, (err, session) => {
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
    Update.session(session, { $push: { reqs: request } }, (err, session) => {
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
  const now = new Date();

  // SESSION OBJECT FUNCTIONS
  session.identify = Identify.bind(session);
  session.flash = Flash.bind(session);
  session.save = Update.session_save.bind(session);

  // Expire and clear flash data
  for (const k in session.flash_data) {
    if (
      session.flash_data[k].endurance !== 'indefinite' &&
      (!session.flash_data[k].endurance || !(session.flash_data[k].endurance - 1))
    ) {
      delete session.flash_data[k];
    } else if (session.flash_data[k].endurance !== 'indefinite') {
      session.flash_data[k].endurance--;
    }
  }

  Update.session(
    session,
    {
      $set: {
        flash_data: session.flash_data,
      },
    },
    function (err) {
      if (err) {
        log.error('sessionFlash update error', err);
      }

      cb(null, this);

      if (opts.log_all) {
        log.timer('sessionFlash', now);
      }
    }.bind(session),
  );
}

// =====================

function Identify(name) {
  Update.session(this, { $set: { name } }, (err) => {
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
    endurance,
  };
  Update.session(this, { $set: { flash_data: this.flash_data } }, (err) => {
    if (err) {
      log.error('flash data save error', err);
    }
    if (cb) {
      cb(err);
    }
  });
}

// =====================

const Update = {
  session_save(cb) {
    const session = this;
    Update.session(
      session,
      {
        $set: session,
      },
      cb,
    );
  },

  session(session, upd, cb) {
    const keys = Update._keys(upd);

    Session.findByIdAndUpdate(session._id, upd, {
      new: true,
      fields: SESSION_FIELDS,
      upsert: true,
    })
      .lean()
      .exec(function (err, doc) {
        if (err) {
          log.error('Update.session error [', this, ']', err);
        } else if (!doc) {
          log.error('Update.session no session found!', session);
        } else if (doc && opts.log_all) {
          log.session(doc, 'Update.session success [', this, ']');
        }

        if (cb) {
          cb(err, doc);
        }
      }.bind(keys));
  },

  request(socket, updIn, cb) {
    const upd = {};

    for (const k in updIn) {
      // $push: { clicks: id }
      // -->
      // $push: { reqs.$.clicks: id }

      if (!upd[k]) {
        upd[k] = {};
      }

      for (const k2 in updIn[k]) {
        const reqKey = `reqs.$.${k2}`;
        upd[k][reqKey] = updIn[k][k2];
      }
    }

    const keys = Update._keys(upd);

    Session.update(
      {
        _id: socket.session._id,
        'reqs._id': socket.req._id,
      },
      upd,
      function (err, { n }) {
        const socket = this.socket;

        if (err) {
          log.error(
            'Update.request error [',
            this.keys,
            ']',
            socket.session._id,
            socket.req._id,
            err,
          );
        } else if (n < 1) {
          log.error('Update.request not found!', socket.session._id, socket.req._id);
        } else if (opts.log_all) {
          log.session(socket.session, 'Update.request success [', this.keys, ']');
        }

        if (cb) {
          return cb(err);
        }
      }.bind({
        socket,
        keys,
      }),
    );
  },

  _keys(params) {
    const keys = [];

    for (const k in params) {
      for (const k2 in params[k]) {
        keys.push(k2);
      }
    }

    return keys;
  },
};

// =====================

function getCookies(src) {
  const cookies = cookie.parse(src || '');
  for (const k in cookies) {
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

const AES = {
  encrypt(value) {
    return CryptoJS.AES.encrypt(value, opts.secret).toString();
  },
  decrypt(encrypted) {
    return CryptoJS.AES.decrypt(encrypted, opts.secret).toString(CryptoJS.enc.Utf8);
  },
};

// =====================

function sessions(options, cb) {
  if (!cb) {
    cb = options;
    options = { is_bot: false };
  }

  const n = 32;

  Session.find(options)
    .sort({ date: 'desc' })
    .limit(n)
    .exec((err, results) => {
      if (err) {
        log.error('Sessions query error:', err);
      }

      cb(err, results);
    });
}
