/*
 * node-analytics
 * Copyright(c) 2016 Andrew Lake
 * MIT Licensed
 */

// defaults
var fs = require('fs')
,   path = require('path')
,   http = require('http')

// installed
var get_ip = require('ipware')().get_ip
,   mongoose = require('mongoose')
,   useragent = require('useragent')
,   maxmind = require('maxmind')
,   cookie = require('cookie')
,   async = require('async')
,   s_io = require('socket.io')
,   colours = require('colors/safe')
,   CryptoJS = require('crypto-js')

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
              , setCookies
              , newRequest
            ],
            function(err, results){
                if(err) log.error(err)

                var new_session = results[0];   // [getSession] boolean
                var request = results[2];       // [newRequest] request document

                async.series([
                    function(callback){
                        sessionData(new_session, callback)
                    }
                  , function(callback){
                        sessionSave(new_session, request, callback)
                  }
                ],
                function(err){
                    if(err) log.error(err);
                    next();
                });
            }
        );
        
        // populate var session; returns boolean on whether newly formed
        function getSession(callback){
            var cookies = cookie.parse(req.headers.cookie || '');

            // cookies.na_session  :: session._id
            // cookies.na_user     :: session.user

            // Establish session: new/old session? new/old user?
            if(cookies.na_session){
                var na_session = decrypt(cookies.na_session);
                
                log('Session cookie found:', na_session)

                Session.findById(na_session, function(err, result){
                    if(err) log.error(err)

                    if(!result){
                        log.error('Session not found :: id[cookie]:', na_session)

                        // send to check if user instead
                        if(cookies.na_user) userSession();
                        else newSession();
                    }
                    else {
                        log('Session continues :: id:', na_session)
                        session = result;

                        callback(null, false);
                    }
                })
            }
            else if(cookies.na_user) userSession();
            else newSession();

            function userSession(){
                var na_user = decrypt(cookies.na_user);
                
                log('User cookie found:', na_user)
                session = new Session({ user: na_user })
                log('Old user, new session :: user:', session.user)

                callback(null, true)
            }
            function newSession(){
                session = new Session();   
                session.user = session._id.toString();
                log('New user, new session :: user:', session.user)

                callback(null, true)
            }
        }

        // set cookies
        function setCookies(callback){
            // Set cookies
            var session_enc = encrypt(session._id.toString());
            var user_enc = encrypt(session.user.toString());
            
            res.cookie('na_session', session_enc, {
                maxAge:     1000 * 60 * 15              // 15 mins
              , httpOnly:   true
            });
            res.cookie('na_user', user_enc, {
                maxAge:     1000 * 60 * 60 * 24 * 365   // 1 year
              , httpOnly:   true
            });

            return callback(null);
        }
            
        // return new request document
        function newRequest(callback){
            var request = new Request();
            request.host = req.hostname;
            request.url = req.url;

            // populate request query
            for(var field in req.query){
                if(field === 'ref') request.ref = req.query[field]
                else {
                    request.query.push({
                        field: field
                      , value: req.query[field]
                    })
                }
            }

            // add request index cookie
            var req_index = session.reqs.length;
            var index_enc = encrypt(req_index);
            res.cookie('na_req_index', index_enc, {
                maxAge:     1000 * 60 * 15              // 15 mins
              , httpOnly:   true
            })

            // return request object: will be added at sessionSave();
            callback(null, request)
        }
            
        // append session data
        function sessionData(new_session, callback){
            // no need to run if picking up from old session
            if(!new_session) return callback(null);
            
            async.parallel([
                    getIp
                  , getLocation
                  , getSystem
                ],
                function(err){
                    if(err) callback(err);
                    callback(null);
                }
            );
            
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
        }
        
        // save / update session to DB & proceed to socket
        function sessionSave(new_session, request, callback){
            if(new_session){
                session.reqs.push(request);
                session.save(function(err){
                    if(err) return callback('session save error')
                    
                    log.session(session, 'session active [ new ]')
                    return callback(null);
                });
            }
            else {
                // an old session: all that needs be updated is request
                update.session(session, {$push: {reqs: request}}, function(err){
                    if(err) return callback('new request not added to session', session._id)

                    log.session(session, 'session active [ updated ]')
                    callback(null);
                });
            }
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
    var Request_Schema = mongoose.Schema({
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
        var session_id = decrypt(cookies.na_session);
        var req_index = decrypt(cookies.na_req_index);
        
        var session, request;
        var session_start = Date.now();
        var blurred = 0;
        var blurring = Date.now();
        
        // Get session
        if(session_id){
            Session.findById(session_id, function(err, result){
                if(err) return log.error('Session find error :: id[socket]', session_id, err)
                if(!result) return log.error('Session not found :: id[socket]', session_id)

                // set regional session and request
                session = result;
                request = session.reqs[req_index];
                // could alternatively get request by session.reqs.id with req_id cookie
                
                // log and initiate socket sensitivity
                log.session(session, 'socket connected, request:', request._id)
                socketResponse();
            })
        }
        
        function socketResponse(){
            // session updates
            if(session.is_bot){
                update.session(session, { is_bot: false });
                //log.session(session, 'socket is_bot in [', false, ']')
            }
            
            if(!session.resolution){
                socket.on('resolution', function(params){
                    update.session(session, { resolution: params });
                });
            }
            
            // request updates
            socket.on('click', function(id){
                update.request(session, request, { $push: { clicks : id }})
                //session.reqs[req_index].clicks.push(id);
                log.session(session, 'socket click in [', id, ']')
                //request.clicks.push(id);
            })
            socket.on('reach', function(id){
                update.request(session, request, { $push: { reaches: id }})
                //session.reqs[req_index].reaches.push(id);
                log.session(session, 'socket reach in [', id, ']')
                //request.reaches.push(id);
            })
            socket.on('pause', function(params){
               update.request(session, request, { $push: { pauses: params }})
               //session.reqs[req_index].pauses.push(params);
               log.session(session, 'socket pause in [', params, ']')
               //request.reaches.push(params);
            })
            
            // session timer
            socket.on('blur', function(){
                blurring = Date.now();
            })
            socket.on('focus', function(){
                blurred += Date.now() - blurring;
            })

            // Disconnection
            socket.on('disconnect', function() {
                // request time, sans blurred time
                var t = (Date.now() - session_start - blurred) / 1000;
                
                // total session time; begin with this request
                var session_t = t;
                for(var i = 0; i < session.reqs.length; i++) session_t += session.reqs[i].time;
                
                // update request & session
                request.time = t;
                update.request(session, request, { time: t });
                
                update.session(session, { session_time: session_t });
                //update.request(session, request);
                
                log.session(session, 'socket disconnected');
            })
        }
    })
    
    log('Websocket server established');
}

// toolbox
var update = {
    session: function(session, params, callback){
        var keys = update._keys(params);
        
        Session.update({_id: session._id}, params, function(err, raw){
            if(err) log.error('session update error [', keys, ']', session._id, err);
            else log.session(session, 'session updated [', keys, ']', session._id);
            
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
                    var key = update._reqkey(l)
                    params.$push[key] = params_in.$push[l];
                }
            }
            else {
                var key = update._reqkey(k)
                params[key] = params_in[k];
            }
        }
        
        var keys = update._keys(params);
        
        Session.update({_id: session._id, "reqs._id": request._id}, params, function(err, raw){
            if(err) log.error('request update error [', keys, ']', request._id, err);
            else log.session(session, 'request updated [', keys, ']');
            
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

function encrypt(text){
    return CryptoJS.AES.encrypt(text, '78hokaport74216lazoo').toString();
}
function decrypt(code){
    var bytes  = CryptoJS.AES.decrypt(code.toString(), '78hokaport74216lazoo');
    return bytes.toString(CryptoJS.enc.Utf8);
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

/*function encrypt(text){
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
            }*/