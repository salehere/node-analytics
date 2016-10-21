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
,   colours = require('colors/safe');

// globals
var db,
    geo_lookup,
    Session,
    Request,
    io;

// -------------------------------------------------------------

module.exports = analytics;
module.exports.sessions = sessions;

var opts = {
    db_host:    'localhost'
  , db_port:    27017
  , db_name:    'node_analytics_db'
  , ws_port:    8080
  , geo_ip:     true
  , mmdb:       'GeoLite2-City.mmdb'
  , log:        true
  , log_pre:    colours.green('node-analytics') + ' ||'
  , error_log:  true
  , error_pre:  colours.green('node-analytics') + ' ' + colours.red('ERROR') + ' ::'
};

console.log(colours.green('node-analytics'), "active: wait for MongoDB, GeoIP, & WebSocket");
console.log(colours.green('node-analytics'), "don't forget to copy", colours.red('node-analytics-client.js'), "to public directory");

function analytics(opts_in){
    for(var k in opts_in) opts[k] = opts_in[k];
    
    mongoDB();
    geoDB();
    socketInit();
    
    // HTTP request:
    return function(req, res, next){

        // Skip cases
        if(req.url.indexOf('/socket.io/?EIO=') == 0)
            return next();

        // =================================

        // populate var session; returns boolean on whether newly formed
        function getSession(callback){
            var cookies = cookie.parse(req.headers.cookie || '');

            // cookies.na_session  :: session._id
            // cookies.na_user     :: session.user

            // Establish session: new/old session? new/old user?
            if(cookies.na_session){
                log('Session cookie found:', cookies.na_session);

                Session.findById(cookies.na_session, function(err, session){
                    if(err)
                        log.error(err);

                    if(!session){
                        log.error('Session not found :: id[cookie]:', cookies.na_session);

                        // send to check if user instead
                        if(cookies.na_user)
                            userSession();
                        else
                            newSession();
                    }
                    else {
                        log('Session continues :: id:', cookies.na_session);
                        session.continued = true;
                        callback(null, session);
                    }
                })
            }
            else if(cookies.na_user)
                userSession();
            else
                newSession();

            // ====================

            function userSession(){
                log('Old user, new session :: user:', cookies.na_user);
                callback(null, new Session({ user: cookies.na_user }))
            }
            function newSession(){

                // Initiate session to get _id
                let session = new Session();
                session.user = session._id.toString();

                log('New user, new session :: user:', session.user);

                callback(null, session)
            }
        }

        // set cookies
        function setCookies(session, callback){
            // Set cookies
            res.cookie('na_session', session._id.toString(), {
                maxAge:     1000 * 60 * 15              // 15 mins
                , httpOnly:   true
            });
            res.cookie('na_user', session.user, {
                maxAge:     1000 * 60 * 60 * 24 * 365   // 1 year
                , httpOnly:   true
            });

            callback(null, session)
        }

        // append session data
        function sessionData(session, callback){

            if(session.continued){
                callback(null, session);
                return true;
            }

            async.parallel([
                    getIp,
                    getLocation,
                    getSystem
                ],
                function(err){
                    return err ? callback(err) : callback(null, session);
                }
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

                try{
                    if(loc.city) session.geo.city = loc.city.names.en;
                    if(loc.subdivisions) session.geo.state = loc.subdivisions[0].iso_code;
                    if(loc.country) session.geo.country = loc.country.iso_code;
                    if(loc.continent) session.geo.continent = loc.continent.code;
                    if(loc.location) session.geo.time_zone = loc.location.time_zone;
                }
                catch(e){ log.error('geoIP error:', e); }

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
        function newRequest(session, callback){
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
                httpOnly:   true
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

                    log.session(session, 'session active [ new ]');
                    return callback(null, session);
                });
            }
            else {
                // an old session: all that needs be updated is request
                update.session(session, {$push: {reqs: request}}, function(err){
                    if(err)
                        return callback('db session update error');

                    log.session(session, 'session active [ updated ]');
                    callback(null, session);
                });
            }
        }

        // =================================

        async.waterfall([
                getSession
              , setCookies
              , newRequest
              , sessionData
              , sessionSave
            ],
            function(err, session){
                if(err){
                    log.error(err);
                    next();
                    return false;
                }
                req.node_analytics = session;
                next();
            }
        );
    }
}

function mongoDB(){
    // Connect to MongoDB
    var db_url = 'mongodb://' + opts.db_host + ':' + opts.db_port + '/' + opts.db_name;
    db = mongoose.connect(db_url).connection;
    db.on('error', function(err) {
        log.error('MongoDB error: Data will not be saved :: err:', err)
    });
    db.once('open', function() {
        log('MongoDB connection successful')
    });
    
    // Schema
    var Request_Schema = mongoose.Schema({
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
    
    var Session_Schema = mongoose.Schema({
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
    });
    
    Request = mongoose.model('Request', Request_Schema);
    Session = mongoose.model('Session', Session_Schema);
}

function geoDB(){
    // Check for mmdb
    if(opts.geo_ip){
        fs.stat(opts.mmdb, function(err, stats){
            if(err) return log.error(err, 'GeoIP DB file not found :: Path:', opts.mmdb);

            try {
                geo_lookup = maxmind.open(opts.mmdb);
            }
            catch(e){ return log.error('GeoIP DB read error :: err:', e) }

            log('GeoIP DB loaded successfully')
        })
    }
}

function socketInit(){
    io = s_io(opts.ws_port);
    io.use(function(socket, next){
        if(socket.handshake.headers.cookie){
            var cookies = cookie.parse(socket.handshake.headers.cookie);
            if(cookies && cookies.na_session) next();
        }
        else log.error('Socket authentication error; no session cookie')
    });
    io.on('connection', function(socket) {
        var cookies = cookie.parse(socket.handshake.headers.cookie || '');
        var session_id = cookies.na_session;
        var req_index = cookies.na_req_index;
        
        var session, request;
        var session_start = Date.now();
        var blurred = 0;
        var blurring = Date.now();
        
        // Get session
        if(session_id){
            Session.findById(session_id, function(err, result){
                if(err) return log.error('Session find error :: id[socket]', session_id, err);
                if(!result) return log.error('Session not found :: id[socket]', session_id);

                // set regional session and request
                session = result;
                request = session.reqs[req_index];
                // could alternatively get request by session.reqs.id with req_id cookie
                
                // log and initiate socket sensitivity
                if(request){
                    log.session(session, 'socket connected, request:', request._id);
                    socketResponse();
                }
                else {
                    log.error('socket connected, request not found');
                    socketResponse(true);
                }
            })
        }
        
        function socketResponse(if_req){
            // session updates
            if(session.is_bot){
                update.session(session, { is_bot: false });
            }
            
            if(!session.resolution){
                socket.on('resolution', function(params){
                    update.session(session, { resolution: params });
                });
            }
            
            // request updates
            socket.on('click', function(id){
                if(if_req) update.request(session, request, { $push: { clicks : id }});
                log.session(session, 'socket click in [', id, ']')
            });
            socket.on('reach', function(id){
                if(if_req) update.request(session, request, { $push: { reaches: id }});
                log.session(session, 'socket reach in [', id, ']')
            });
            socket.on('pause', function(params){
               if(if_req) update.request(session, request, { $push: { pauses: params }});
               log.session(session, 'socket pause in [', params, ']')
            });
            
            // session timer
            socket.on('blur', function(){
                blurring = Date.now();
            });
            socket.on('focus', function(){
                blurred += Date.now() - blurring;
            });

            // Disconnection
            socket.on('disconnect', function() {
                // request time, sans blurred time
                var t = (Date.now() - session_start - blurred) / 1000;
                
                // total session time; begin with this request
                var session_t = t;
                for(var i = 0; i < session.reqs.length; i++) session_t += session.reqs[i].time;
                
                // update request & session
                request.time = t;
                if(if_req) update.request(session, request, { time: t });
                
                update.session(session, { session_time: session_t });
                
                log.session(session, 'socket disconnected');
            })
        }
    });
    
    log('Websocket server established');
}

var update = {
    session: function(session, params, callback){
        var keys = update._keys(params);
        
        Session.update({_id: session._id}, params, function(err, raw){
            if(err) log.error('session update error [', keys, ']', session._id, err);
            else log.session(session, 'session updated [', keys, ']');
            
            if(callback) return callback(err);
        })
    },
    request: function(session, request, params_in, callback){
        //update.request(session, request, { $push: { clicks : id }})
        //update.request(session, request, { time: t })
        
        var params = {};
        
        for(var k in params_in){
            if(k === '$push'){
                if(!params.$push) params.$push = {};
                
                for(var l in params_in.$push){
                    var key = update._reqkey(l);
                    params.$push[key] = params_in.$push[l];
                }
            }
            else {
                var key = update._reqkey(k);
                params[key] = params_in[k];
            }
        }
        
        var keys = update._keys(params);
        
        Session.update({_id: session._id, "reqs._id": request._id}, params, function(err, raw){
            if(err) log.error('request update error [', keys, ']', request._id, err);
            else log.session(session, 'request updated [', keys, ']', raw);
            
            if(callback) return callback(err);
        })
    },
    _keys: function(params){
        var keys = [];
        for(var k in params){
            if(k === '$push'){ for(var l in params[k]) keys.push(l); }
            else  keys.push(k);
        }
        return keys;
    },
    _reqkey: function(key){
        return 'reqs.$.' + key;
    }
};

var log = function(){
    if(opts.log){
        var args = Array.prototype.slice.call(arguments);
        args = log.prefix(args);
        
        console.log.apply(console, args);
    }
};
log.error = function(){
    if(opts.error_log){
        var args = Array.prototype.slice.call(arguments);
        args = log.prefix(args, true);
        
        console.error.apply(console, args);
    }
};
log.session = function(session){
    if(opts.log){
        // build ident
        var user = session.user;
        var ident = [user.substr(user.length - 6)];
        
        if(session.geo){

            var ks = ['city', 'state', 'country'];
            ks.forEach((k) => {
                if(session.geo[k])
                    ident.push(k);
            });
        }

        ident = ident.join(", ");
        
        // substitute ident for session in args
        var args = Array.prototype.slice.call(arguments);
        args[0] = colours.blue(ident) + ' ||';
        
        // add prefix to start
        args = log.prefix(args);
        
        console.log.apply(console, args);
    }
};
log.prefix = function(args, error){
    // [0] => prefix, [1] => date
    args.unshift(logDate() + ' ||');
    
    if(error) args.unshift(opts.error_pre);
    else args.unshift(opts.log_pre);
    
    return args;
    
    function logDate(){
        var d = new Date();
        return  d.getFullYear() + '/' +
                fZ(d.getMonth() + 1) + '/' +
                fZ(d.getDate()) + ' ' +
                fZ(d.getHours()) + ':' + 
                fZ(d.getMinutes()) + ':' + 
                fZ(d.getSeconds()) + ' ' +
                tz(d);

        function fZ(v){ return ('0' + v).slice(-2); }
        function tz(d){
             var m = d.getTimezoneOffset() / -60;
             if(m >= 0) return 'GMT+' + m;
             return 'GMT' + m;
        }
    }
};

function sessions(options, callback){
    if(!callback){
        callback = options;
        options = {is_bot: false}
    }
    var n = 32;
    
    Session.find(options)
            .sort({date: 'desc'})
            .limit(n)
            .exec(function(err, results){
                if(err) log.error('Sessions query error:', err);
                callback(err, results)
            });
}