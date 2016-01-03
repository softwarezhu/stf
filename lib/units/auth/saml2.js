var http = require('http')
var fs = require('fs')

var express = require('express')
var passport = require('passport')
var SamlStrategy = require('passport-saml').Strategy
var bodyParser = require('body-parser')

var logger = require('../../util/logger')
var urlutil = require('../../util/urlutil')
var jwtutil = require('../../util/jwtutil')

module.exports = function(options) {
  var log = logger.createLogger('auth-saml2')
    , app = express()
    , server = http.createServer(app)

  app.set('strict routing', true)
  app.set('case sensitive routing', true)
  app.use(bodyParser.urlencoded({ extended: false }))

  app.use(passport.initialize())
  passport.serializeUser(function(user, done) {
	  done(null, user);
  });
  passport.deserializeUser(function(user, done) {
	  done(null, user);
  });

  var verify = function(profile, done) {
    return done(null, profile)
  }

  var cert = options.saml.certPath ? fs.readFileSync(options.saml.certPath).toString() : null
  var strategy = new SamlStrategy({
    path: '/auth/saml/callback'
  , entryPoint: options.saml.entryPoint
  , issuer: options.saml.issuer
  , cert: cert
  }, verify)

  passport.use(strategy)

  app.get('/auth/saml/'
  , passport.authenticate('saml', {
      failureRedirect: '/auth/saml/'
    , failureFlash: true
    , session: false
    })
  , function(req, res) {
      res.redirect('/auth/saml/')
    })


  app.post('/auth/saml/callback'
  , passport.authenticate('saml', {
    failureRedirect: '/auth/saml/'
  , failureFlash: true
  , session: false
  })
  , function(req, res) {
// TODO: fix req parameter
//    if (req.user.email) {
      if(req.user.nameID) {
        var email = req.user.nameID
        res.redirect(urlutil.addParams(options.appUrl, {
          jwt: jwtutil.encode({
            payload: {
              email: email
            , name: email.split('@', 1).join('')
            }
          , secret: options.secret
          , header: {
              exp: Date.now() + 24 * 3600
            }
          })
        }))
      }
      else {
        log.warn('Missing email in profile', req.user)
        res.redirect('/auth/saml/')
      }
    })

  server.listen(options.port)
  log.info('Listening on port %d', options.port)
}
