if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const config  = require( './config' )

var pkRouter = require('./routes/projetkhiron');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


var cors = "";
if(config.host.cors && config.host.cors.trim().length > 0) {
  cors = config.host.cors;
}

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', cors);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT,DELETE");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, Tenant");
  next();
});

// app.use('/', indexRouter);
// app.use('/users', usersRouter);
app.use('/projetkhiron', pkRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {

  res.status(404);
  res.render('error', { error: {message:'Not Found', code:404} });
  //next({error : {name:'404', message:'not found'}});
  //next(createError(404, {stack:''}));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  console.log(err);
  // render the error page
  res.status(err.status || 500);
  res.render('error', { error: err });
});

module.exports = app;
