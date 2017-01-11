/*
 * node-analytics
 * Copyright(c) 2016 Andrew Lake
 * MIT Licensed
 */

'use strict';

// defaults
var fs = require('fs')
,   path = require('path')
,   http = require('http')
,   crypto = require('crypto');

// installed
var get_ip = require('ipware')().get_ip
,   mongoose = require('mongoose')
,   useragent = require('useragent')
,   maxmind = require('maxmind')
,   cookie = require('cookie')
,   async = require('async')
,   s_io = require('socket.io')
,   colours = require('colors/safe'),
    log = require('andrao-logger')('NODE ANALYTICS');

// globals
var db,
    geo_lookup,
    io = false;

// -------------------------------------------------------------

let Request_Schema = mongoose.Schema({
    host: String
    , url: { type: String, index: true }
    , query: [{ field: String, value: String }]
    , ref: { type: String, index: true }
    , method: { type: String }
    , time: Number
    , reaches: [String]
    , pauses: [{
        section: String
        , time: Number
    }]
    , clicks: [String]
});
let Session_Schema = mongoose.Schema({
    user: { type: String, index: true }
    , date: { type: Date, default: Date.now }
    , ip: String
    , is_bot: { type: Boolean, default: true }
    , geo: {
        city:    { type: String, index: true }
        , state:   { type: String, index: true }
        , country: { type: String, index: true }
        , continent: { type: String, index: true }
        , time_zone: { type: String, index: true }
    }
    , system: {
        os: {
            name: String
            , version: String
        }
        , browser: {
            name: String
            , version: String
        }
    }
    , time: Number
    , resolution: {
        width: Number
        , height: Number
    }
    , reqs: [Request_Schema]
    , state: String
    , flash_data: mongoose.Schema.Types.Mixed
});

let Request = mongoose.model('Request', Request_Schema);
let Session = mongoose.model('Session', Session_Schema);

module.exports = analytics;
module.exports.sessions = sessions;

var opts = {
    db_host:    'localhost'
  , db_port:    27017
  , db_name:    'node_analytics_db'
  , ws_port:    8080
  , ws_server:  false
  , geo_ip:     true
  , mmdb:       'GeoLite2-City.mmdb'
  , log:        true
  , error_log:  true
  , secure:     true
};

log("active: wait for MongoDB, GeoIP, & WebSocket");
log("don't forget to copy", colours.red('node-analytics-client.js'), "to public directory");

function mongoDB(cb){
    // Connect to MongoDB
    var db_url = 'mongodb://' + opts.db_host + ':' + opts.db_port + '/' + opts.db_name;
    db = mongoose.connect(db_url).connection;
    db.on('error', function(err) {
        log.error('MongoDB error: Data will not be saved :: err:', err)
    });
    db.once('open', function() {
        log('MongoDB connection successful');
        cb(null);
    });
}

function geoDB(cb){
    // Check for mmdb
    if(opts.geo_ip){
        maxmind.open(opts.mmdb, (err, mmdb) => {
            if(err){
                log.error('GeoIP DB open error', opts.mmdb, err);
                return cb(true)
            }

            geo_lookup = mmdb;
            log('GeoIP DB loaded successfully');
            cb(null);
        });
    }
    else {
        log('GeoIP disabled');
        cb(null);
    }
}

function socketInit(cb){

    io = opts.ws_server ? s_io.listen(opts.ws_server) : s_io(opts.ws_port);

    io.use(function(socket, next){
        if(socket.handshake.headers.cookie){

            let cookies = socketCookies(socket);
            if(cookies && cookies.na_session)
                next();
        }
        else log.error('Socket authentication error; no session cookie')
    });

    io.on('connection', socketConnection);

    log('Websocket server established');

    cb(null);
}

// =====================

function socketCookies(socket){
    return cookie.parse(socket.handshake.headers.cookie || '');
}

function socketConnection(socket){

    let cookies = socketCookies(socket);

    socket.session_start = Date.now();
    socket.blurred = 0;
    socket.blurring = Date.now();
    socket.req_index = cookies.na_req_index;
    socket.session_id = cookies.na_session;

    // Get session
    if(socket.session_id){
        Session.findById(socket.session_id, function(err, session){
            if(err)
                return log.error('Session find error :: id[socket]', this.session_id, err);
            if(!result)
                return log.error('Session not found :: id[socket]', this.session_id);

            // set regional session and request
            this.session = session;
            this.request = this.session.reqs[this.req_index];

            // could alternatively get request by session.reqs.id with req_id cookie

            // log and initiate socket sensitivity
            if(request){
                if(opts.log)
                    log.session(session, 'socket connected, request:', this.request._id);

                socketResponse(this);
            }
            else {
                log.error('socket connected, request not found');
                socketResponse(this, true);
            }
        }.bind(socket));
    }

    // =============

    function socketResponse(socket, if_req){

        // session updates from the client

        if(if_req)
            socket.if_req = if_req;

        if(socket.session.is_bot)
            update.session(socket.session, { $set: { is_bot: false}});

        if(!socket.session.resolution)
            socket.on('resolution', _socket.resolution.bind(socket));

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

let _socket = {
    click: function(id){
        if(this.if_req)
            update.request(this, { $push: { clicks : id }});

        if(opts.log)
            log.session(this.session, 'socket click in [', id, ']')
    },
    reach: function(id){
        if(this.if_req)
            update.request(this, { $push: { reaches: id }});

        if(opts.log)
            log.session(this.session, 'socket reach in [', id, ']')
    },
    pause: function(params){
        if(this.if_req)
            update.request(this, { $push: { pauses: params }});

        if(opts.log)
            log.session(this.session, 'socket pause in [', params, ']')
    },

    blur: function(){
        this.blurring = Date.now();
    },

    focus: function(){
        this.blurred += Date.now() - this.blurring;
    },

    resolution: function(params){
        update.session(this.session, { $set: { resolution: params }});
    },

    disconnect: function(){
        // request time, sans blurred time
        let t = (Date.now() - this.session_start - this.blurred) / 1000;

        // total session time; begin with this request
        let session_t = t;
        for(let i = 0; i < this.session.reqs.length; i++)
            session_t += this.session.reqs[i].time;

        // update request & session
        this.request.time = t;
        if(this.if_req)
            update.request(this, { $set: { time: t }});

        update.session(this.session, { $set: { session_time: session_t }});

        if(opts.log)
            log.session(this.session, 'socket disconnected');
    }
};

// ===============

function analytics(opts_in){
    for(var k in opts_in)
        opts[k] = opts_in[k];

    async.parallelLimit([
        mongoDB,
        socketInit,
        geoDB,
    ], 2, (err) => {
        if(err)
            return log.error('start-up interrupted');

        log(colours.green('NODE ANALYTICS READY'));
    });

    // HTTP request:
    return function(req, res, next){

        // Skip cases
        if(req.url.indexOf('/socket.io/?EIO=') == 0)
            return next();

        async.waterfall([
            function(cb){
                getSession(req, res, cb);
            },
            setCookies,
            sessionData,
            newRequest,
            sessionSave,
            sessionFlash
        ], function(err, session){
            if(err){
                log.error(err);
                next();
                return false;
            }
            req.node_analytics = session;
            next();
        });
    }
}

// =====================

// populate var session; returns boolean on whether newly formed
function getSession(req, res, callback){
    var cookies = cookie.parse(req.headers.cookie || '');

    // cookies.na_session  :: session._id
    // cookies.na_user     :: session.user

    // Establish session: new/old session? new/old user?
    if(cookies.na_session){
        if(opts.log)
            log('Session cookie found:', cookies.na_session);

        Session.findById(cookies.na_session, function(err, session){
            if(err){
                log.error(err);
                return callback(err);
            }

            if(!session){
                log.error('Session not found :: id[cookie]:', this.cookies.na_session);

                // send to check if user instead
                if(cookies.na_user)
                    userSession();
                else
                    newSession();
            }
            else {
                if(opts.log)
                    log('Session continues :: id:', this.cookies.na_session);

                session.continued = true;

                callback(null, this.req, this.res, session);
            }

        }.bind({
            cookies: cookies,
            req: req,
            res: res
        }))
    }
    else if(cookies.na_user)
        userSession();
    else
        newSession();

    // ====================

    function userSession(){
        if(opts.log)
            log('Old user, new session :: user:', cookies.na_user);

        callback(null, req, res, new Session({ user: cookies.na_user }))
    }
    function newSession(){

        // Initiate session to get _id
        let session = new Session();
        session.user = session._id.toString();

        if(opts.log)
            log('New user, new session :: user:', session.user);

        callback(null, req, res, session)
    }
}

// set cookies
function setCookies(req, res, session, callback){
    // Set cookies
    res.cookie('na_session', session._id.toString(), {
        maxAge:     1000 * 60 * 15,              // 15 mins
        httpOnly:   true,
        secure:     opts.secure
    });
    res.cookie('na_user', session.user, {
        maxAge:     1000 * 60 * 60 * 24 * 365,   // 1 year
        httpOnly:   true,
        secure:     opts.secure
    });

    callback(null, req, res, session)
}

// append session data
function sessionData(req, res, session, callback){

    if(session.continued){
        callback(null, req, res, session);
        return true;
    }

    async.parallelLimit([
            getIp,
            getLocation,
            getSystem
        ], 2,
        function(err){
            return err ? callback(err) : callback(null, this.req, this.res, this.session);
        }.bind({
            req: req,
            res: res,
            session: session
        })
    );

    // ======================

    // .ip
    function getIp(cb){
        session.ip = get_ip(req).clientIp;
        cb(null)
    }

    // .geo :: .city, .state, .country
    function getLocation(cb){
        if(!geo_lookup)
            return cb(null);

        var loc = geo_lookup.get(session.ip);

        if(loc){
            try {
                if(loc.city) session.geo.city = loc.city.names.en;
                if(loc.subdivisions) session.geo.state = loc.subdivisions[0].iso_code;
                if(loc.country) session.geo.country = loc.country.iso_code;
                if(loc.continent) session.geo.continent = loc.continent.code;
                if(loc.location) session.geo.time_zone = loc.location.time_zone;
            }
            catch(e){
                log.error('geoIP error:', e);
            }
        }

        cb(null)
    }

    // .system :: .os{, .broswer{ .name, .version
    function getSystem(cb){
        var agent = useragent.parse(req.headers['user-agent']);
        var os = agent.os;
        session.system.browser.name = agent.family;
        session.system.browser.version = agent.major + '.' + agent.minor + '.' + agent.patch;

        session.system.os.name = os.family;
        session.system.os.version = os.major + '.' + os.minor + '.' + os.patch;

        cb(null)
    }
}

// return new request document
function newRequest(req, res, session, callback){
    let request = {
        host: req.hostname,
        url: req.url,
        method: req.method
    };

    // populate request query
    for(let field in req.query){
        if(field === 'ref')
            request.ref = req.query[field];
        else {
            if(!request.query)
                request.query = [];

            request.query.push({
                field: field
                , value: req.query[field]
            })
        }
    }

    // add request index cookie
    let req_index = session.reqs.length;
    res.cookie('na_req_index', req_index, {
        maxAge:     1000 * 60 * 15,             // 15 mins
        httpOnly:   true,
        secure:     opts.secure
    });

    // return request object: will be added at sessionSave();
    callback(null, session, request)
}

// save / update session to DB & proceed to socket
function sessionSave(session, request, callback){
    if(!session.continued){
        session.reqs.push(request);
        session.save(function(err){
            if(err)
                return callback('db session save error');

            if(opts.log)
                log.session(session, 'session active [ new ]');

            return callback(null, this);

        }.bind(session));
    }
    else {
        // an old session: all that needs be updated is request
        update.session(session, {$push: {reqs: request}}, function(err, doc){
            if(err)
                return callback('db session update error');

            if(opts.log)
                log.session(doc, 'session active [ updated ]');

            callback(null, doc);
        });
    }
}

function sessionFlash(session, callback){
    session.flash = Flash.bind(session);

    // Expire and clear flash data
    for(let k in session.flash_data){
        if(!session.flash_data[k].endurance || !(session.flash_data[k].endurance - 1))
            delete session.flash_data[k];
        else
            session.flash_data[k].endurance--;
    }

    update.session(session, { $set: { flash_data: session.flash_data }}, function(err){
        if(err)
            log.error('sessionFlash update error', err);

        callback(null, this);

    }.bind(session));
}

function Flash(field, value, endurance, cb){

    // Return saved field value
    if(typeof value === 'undefined'){
        if(!this.flash_data || !this.flash_data[field])
            return null;

        return this.flash_data[field].val;
    }

    // Save new field value for next session
    else {

        // Endurance represents number of page loads that this variable will last for
        //  (Helpful in redirect situations)
        if(typeof endurance === 'function'){
            cb = endurance;
            endurance = 1;
        }
        else if(!endurance)
            endurance = 1;

        if(!this.flash_data)
            this.flash_data = {};

        this.flash_data[field] = {
            val: value,
            endurance: endurance
        };
        update.session(this, { $set: { flash_data: this.flash_data }}, (err, doc) => {
            if(err)
                log.error('flash data save error', err);

            if(cb)
                cb(err);
        });
    }
}

// =====================

let update = {
    session: function(session, params, cb){

        var keys = update._keys(params);

        Session.findByIdAndUpdate(session._id, params, { new: true }, function(err, doc){
            if(err)
                log.error('session update error [', keys, ']', doc._id, err);
            else if(opts.log)
                log.session(doc, 'session updated [', keys, ']');
            
            if(cb)
                return cb(err, doc);
        })
    },
    request: function(socket, params_in, callback){
        
        let params = {};

        for(let k in params_in){
            // $push: { clicks: id }
            // -->
            // $push: { reqs.$.clicks: id }

            if(!params[k])
                params[k] = {};

            for(let k2 in params_in[k]){
                let req_key = 'reqs.$.' + k2;
                params[k][req_key] = params_in[k][k2];
            }
        }

        let keys = update._keys(params);
        
        Session.update({
            _id: socket.session._id,
            "reqs._id": socket.request._id
        }, params, function(err, raw){
            if(err)
                log.error('request update error [', this.keys, ']', this.socket.request._id, err);
            else if(opts.log)
                log.session(this.socket.session, 'request updated [', this.keys, ']', raw);
            
            if(callback)
                return callback(err);

        }.bind({
            socket: socket,
            keys: keys
        }))
    },
    _keys: function(params){

        let keys = [];

        for(let k in params)
            for(let k2 in params[k])
                keys.push(k2);

        return keys;
    }
};

// =====================

function sessions(options, callback){

    if(!callback){
        callback = options;
        options = { is_bot: false };
    }

    var n = 32;

    Session.find(options)
            .sort({date: 'desc'})
            .limit(n)
            .exec(function(err, results){
                if(err)
                    log.error('Sessions query error:', err);

                callback(err, results)
            });
}