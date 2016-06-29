/*
 * node-analytics
 * Copyright(c) 2016 Andrew Lake
 * MIT Licensed
 */

// defaults
var fs = require('fs')
,   path = require('path')
,   http = require('http')
,   crypto = require('crypto')

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
var db
,   geo_lookup
,   Session
,   io


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
}

console.log(colours.green('node-analytics'), "active: wait for MongoDB, GeoIP, & WebSocket")
console.log(colours.green('node-analytics'), "don't forget to copy", colours.red('node-analytics-client.js'), "to public directory")

function analytics(opts_in){
    for(var k in opts_in) opts[k] = opts_in[k];
    
    mongoDB();
    geoDB();
    socketInit();
    
    // HTTP request:
    return function(req, res, next){
        // Otherwise, log page load
        var session;
        
        async.series([
                getSession
              , function(callback){
                    async.parallel([
                            getIp
                          , getLocation
                          , getSystem
                          , getReqData
                        ],
                        function(errs){
                            if(errs) log.error(errs)
                            callback(null);
                        }
                    );
              }
              , saveSession
            ]
          , function(errs){
              if(errs) log.error(errs)
              next();
          }
        )
        
        // .userID >> set cookie
        function getSession(callback){
            
            async.series([
                    setSession
                  , setCookies
                ],
                function(errs){
                    if(errs) log.error(errs)
                    callback(null);
                }
            )
            
            function setSession(callback){
                var cookies = cookie.parse(req.headers.cookie || '');
            
                // cookies.na_session  :: session._id
                // cookies.na_user     :: session.user
                
                // Establish session: new/old session? new/old user?
                if(cookies.na_session){
                    log('Session cookie found:', cookies.na_session)
                    
                    Session.findById(cookies.na_session, function(err, result){
                        if(err) log.error(err)
                        
                        if(!result){
                            log.error('Session not found :: id[cookie]:', cookies.na_session)

                            // send to check if user instead
                            if(cookies.na_user) userSession()
                            else newSession()
                        }
                        else {
                            log('Session continues :: id:', cookies.na_session)
                            session = result;

                            callback(null)
                        }
                    })
                }
                else if(cookies.na_user) userSession()
                else newSession()
                
                function userSession(){
                    log('User cookie found:', cookies.na_user)
                    session = new Session({ user: cookies.na_user })
                    log('Old user, new session :: user:', session.user)

                    callback(null)
                }
                function newSession(){
                    session = new Session();   
                    session.user = session._id.toString();
                    log('New user, new session :: user:', session.user)

                    callback(null)
                }
            }
            
            function setCookies(callback){
                // Set cookies
                res.cookie('na_session', session._id.toString(), {
                    maxAge:     1000 * 60 * 15              // 15 mins
                  , httpOnly:   true
                })
                res.cookie('na_user', session.user, {
                    maxAge:     1000 * 60 * 60 * 24 * 365   // 1 year
                  , httpOnly:   true
                })
                
                callback(null)
            }
            
            function encrypt(text){
                var cipher = crypto.createCipher('aes192', 'a password');
                var encrypted = cipher.update(text, 'utf8', 'hex');
                encrypted += cipher.final('hex');
                
                log('Encrypted', text, encrypted)
                
                return encrypted;
            }
            function decrypt(text){
                var decipher = crypto.createDecipher('aes192', 'a password');
                
                var decrypted = decipher.update(text, 'hex', 'utf8');
                decrypted += decipher.final('utf8');
                
                log('Decrypted', text, decrypted)
                
                return decrypted;
            }
        }
        
        // .ip
        function getIp(callback){
            session.ip = get_ip(req).clientIp
            callback(null)
        }
        
        // .geo :: .city, .state, .country
        function getLocation(callback){
            if(!geo_lookup) return callback(null);
            
            var loc = geo_lookup.get(session.ip)
            
            try{
                if(loc.city) session.geo.city = loc.city.names.en;
                if(loc.subdivisions) session.geo.state = loc.subdivisions[0].iso_code;
                if(loc.country) session.geo.country = loc.country.iso_code;
                if(loc.continent) session.geo.continent = loc.continent.code;
                if(loc.location) session.geo.time_zone = loc.location.time_zone;
            }
            catch(e){ log.error('geoIP error:', e); }
            
            callback(null)
        }
        
        // .system :: .os{, .broswer{ .name, .version
        function getSystem(callback){
            var agent = useragent.parse(req.headers['user-agent']);
            var os = agent.os;
            session.system.browser.name = agent.family;
            session.system.browser.version = agent.major + '.' + agent.minor + '.' + agent.patch

            session.system.os.name = os.family;
            session.system.os.version = os.major + '.' + os.minor + '.' + os.patch
            
            callback(null)
        }
        
        // .req :: .host, .url, .query, .ref
        function getReqData(callback){
            var sesreq = {}
            
            sesreq.host = req.hostname;
            sesreq.url  = req.url;
            sesreq.query = [];
            
            for(var field in req.query){
                if(field === 'ref') sesreq.ref = req.query[field]
                else {
                    sesreq.query.push({
                        field: field
                      , value: req.query[field]
                    })
                }
            }
            
            session.reqs.push(sesreq)
            
            res.cookie('na_req_ind', session.reqs.length - 1, {
                    maxAge:     1000 * 60 * 15              // 15 mins
                  , httpOnly:   true
                })
            
            callback(null)
        }
        
        // CLIENT
        // resolution [once]
        // session_length [total]
        // time
        // reaches
        // pauses
        // clicks
        
        function saveSession(callback){
            // Update DB
            session.save(function(err){
                if(err) return callback(err)
                
                log.session(session, 'Session instantiated')
                callback(null)
            })
        }
    }
}

function mongoDB(){
    // Connect to MongoDB
    var db_url = 'mongodb://' + opts.db_host + ':' + opts.db_port + '/' + opts.db_name
    db = mongoose.connect(db_url).connection;
    db.on('error', function(err) {
        log.error('MongoDB error: Data will not be saved :: err:', err)
    });
    db.once('open', function() {
        log('MongoDB connection successful')
    });
    
    // Schema
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
      , reqs: [{
                host: String
              , url: { type: String, index: true }
              , query: [{ field: String, value: String }]
              , ref: { type: String, index: true }
              , time: Number
              , reaches: [String]
              , pauses: [{
                    section: String
                  , time: Number
                }]
              , clicks: [String]
           }]
    })
    
    Session = mongoose.model('Session', Session_Schema);
}

function geoDB(){
    // Check for mmdb
    if(opts.geo_ip){
        fs.stat(opts.mmdb, function(err, stats){
            if(err) return log.error(err, 'GeoIP DB file not found :: Path:', opts.mmdb)

            try { geo_lookup = maxmind.open(opts.mmdb) }
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
    })
    io.on('connection', function(socket) {
        var cookies = cookie.parse(socket.handshake.headers.cookie || '');
        var session_id = cookies.na_session;
        var req_index = parseInt(cookies.na_req_ind)
        var session;
        
        var session_start = Date.now();
        
        if(session_id){
            Session.findById(session_id, function(err, result){
                if(err) return log.error('Session find error :: id[socket]', session_id, err)
                if(!result) return log.error('Session not found :: id[socket]', session_id)

                session = result;
                log.session(session, 'Socket CONNECTED')
                socketResponse();
            })
        }

        function socketResponse(){
            if(session.is_bot){
                session.is_bot = false;
                log.session(session, 'socket is_bot in [', false, ']')
            }
            
            socket.on('resolution', function(params){
                // Set only once
                if(!session.resolution){
                    session.resolution = params;
                    log.session(session, 'socket resolution in [', params, ']')
                }
            })
            socket.on('click', function(id){
                session.reqs[req_index].clicks.push(id);
                log.session(session, 'socket click in [', id, ']')
            })
            socket.on('reach', function(id){
                session.reqs[req_index].reaches.push(id);
                log.session(session, 'socket reach in [', id, ']')
            })
            socket.on('pause', function(params){
               session.reqs[req_index].pauses.push(params);
               log.session(session, 'socket pause in [', params, ']')
            })

            // Disconnection
            socket.on('disconnect', function() {
                // group session time from req times; update
                var t = (Date.now() - session_start) / 1000;
                session.reqs[req_index].time = t;

                var session_t = 0;
                for(var i = 0; i < session.reqs.length; i++) session_t += session.reqs[i].time;
                session.session_time = session_t;

                sessionSave(session);
                
                log.session(session, 'socket DISCONNECTED');
            })
        }
    })
    
    log('Websocket server established');
}

function sessionSave(session){
    session.save(function(err, saved, numAffected) {
        if(err) return log.error('socket session update error ::', err)
        log.session(saved, 'socket session saved')
    })
}

var log = function(){
    if(opts.log){
        var args = Array.prototype.slice.call(arguments);
        args = log.prefix(args)
        
        console.log.apply(console, args);
    }
}
log.error = function(){
    if(opts.error_log){
        var args = Array.prototype.slice.call(arguments);
        args = log.prefix(args, true)
        
        console.error.apply(console, args);
    }
}
log.session = function(session){
    if(opts.log){
        // build ident
        var user = session.user;
        var ident = user.substr(user.length - 6);
        
        if(session.geo){
            if(session.geo.city){
                ident += ' ' + session.geo.city
                if(session.geo.state) ident += ', ' + session.geo.state
            }
            else if(session.geo.state){
            ident += ' ' + session.geo.state
            if(session.geo.country) ident += ', ' + session.geo.country
        }
        }
        
        // substitute ident for session in args
        var args = Array.prototype.slice.call(arguments);
        args[0] = colours.blue(ident) + ' ||';
        
        // add prefix to start
        args = log.prefix(args)
        
        console.log.apply(console, args);
    }
}
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
                tz(d)

        function fZ(v){ return ('0' + v).slice(-2); }
        function tz(d){
             var m = d.getTimezoneOffset() / 60;
             if(m >= 0) return 'GMT+' + m;
             return 'GMT' + m;
        }
    }
}

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
                if(err) log.error('Sessions query error:', err)
                callback(err, results)
            });
}