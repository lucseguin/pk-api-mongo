if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

var express = require('express');
var router = express.Router();
var mongo = require('mongodb');
var AWS = require('aws-sdk');
const { JWTValidator } = require('aws-cognito-express');
var stream = require('stream');
var readline = require('readline');
var nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');

const MongoClient = mongo.MongoClient;
const ObjectID = mongo.ObjectID;

const config = require('../config')

var AWSaccessKeyId = config.aws.accessKeyId;
var AWSsecretAccessKey = config.aws.secretAccessKey;
var AWSRegion = config.aws.region;
var MONGODB_URI = config.database.connectionstring;

AWS.config.credentials = { "accessKeyId": AWSaccessKeyId, "secretAccessKey": AWSsecretAccessKey, "region": AWSRegion };
AWS.config.update({ region: AWSRegion });
AWS.config.apiVersions = {
    cognitoidentityserviceprovider: '2016-04-18',
    sns: '2010-03-31',
};

const jwtValidator = new JWTValidator({
    region: config.cognito.region,
    userPoolId: config.cognito.userPoolID,
    tokenUse: ['id', 'access'],
    audience: [config.cognito.userPoolsWebClientID]
});

const userAccessAuthorized = (req) => {
    return new Promise((resolve, reject) => {
        if (req.headers.authorization && req.headers.authorization.trim().length > 0) {
            jwtValidator.validate(req.headers.authorization)
                .then(jwtPayload => {
                    resolve(true);
                })
                .catch(err => {
                    reject(false);
                });
        } else {
            reject(false);
        }
    })
}

/* GET users listing. */
router.get('/accounts', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                query = { tenant: req.headers.tenant };
            }

            if (req.query.email && req.query.email.trim().length > 0) {
                query = { ...query, email: req.query.email.trim() };
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /account mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db("projetkhiron").collection("accounts").find(query).toArray(function (err2, result) {
                    if (err2) {
                        console.log("ERROR in get /account mongodb find");
                        console.log(err2.message, err2.code);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/accounts/:role', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /accounts/:role mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                let query = { "role.name": req.params.role };
                if (req.headers.tenant && req.headers.tenant.length > 0) {
                    query = { ...query, tenant: req.headers.tenant };
                }

                client.db("projetkhiron").collection("accounts").find(query).toArray()
                    .then(accounts => {
                        if (accounts)
                            res.json(accounts);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        console.log("ERROR in get /accounts/:role mongodb find");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/account', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /account mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                var tenant = "projetkhiron";
                if (req.headers.tenant && req.headers.tenant.length > 0) {
                    tenant = req.headers.tenant;
                }

                const { _id, firstName, lastName, role, email, phone } = req.body;
                if (_id === '-1') { //new account
                    const { tmpPwd } = req.body;

                    var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();
                    var params = {
                        UserPoolId: config.cognito.userPoolID, /* required */
                        Username: email, /* required */
                        DesiredDeliveryMediums: [
                            "EMAIL",
                        ],
                        ForceAliasCreation: true,
                        TemporaryPassword: tmpPwd,
                        UserAttributes: [
                            {
                                Name: 'email', /* required */
                                Value: email
                            },
                            {
                                Name: 'email_verified',
                                Value: 'true'
                            },
                        ],
                    };

                    cognitoidentityserviceprovider.adminCreateUser(params, function (err2, data) {
                        if (err2) {
                            client.close();
                            console.log("ERROR in put /account cognito adminCreateUser");
                            console.log(err2.message, err2.code);
                            res.status(500);
                            res.render('error', { error: err2 });
                        } else {
                            client.db("projetkhiron").collection("accounts").insertOne({ _id: new ObjectID(), cognitoID: data.User.Username, status: 'offline', statusDevice: 'unknown', lastSeen: new Date(), firstName: firstName, lastName: lastName, role: role, email: email, phone: phone, extra: [], paletteType: 'dark', tenant: tenant })
                                .then(result => {
                                    res.status(200).send('Ok');
                                })
                                .catch(error => {
                                    console.log("ERROR in put /account mongodb insertOne");
                                    console.log(error.message, error.code);
                                    res.status(500)
                                    res.render('error', { error: error });
                                })
                                .finally(() => {
                                    client.close();
                                });
                        }
                    });
                } else { //existing account
                    let query = { _id: new ObjectID(_id) };
                    client.db("projetkhiron").collection("accounts").updateOne(query, { $set: { firstName: firstName, lastName: lastName, role: role, email: email, phone: phone } }, { upsert: false })
                        .then(result => {
                            res.status(200).send('Ok');
                        })
                        .catch(error => {
                            console.log("ERROR in put /account mongodb updateOne");
                            console.log(error.message, error.code);
                            res.status(500);
                            res.render('error', { error: error });
                        })
                        .finally(() => {
                            client.close();
                        });
                }
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.delete('/account', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in delete /account mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                const { _id, cognitoID } = req.query;

                var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();
                var params = {
                    UserPoolId: config.cognito.userPoolID, /* required */
                    Username: cognitoID /* required */
                };
                cognitoidentityserviceprovider.adminDeleteUser(params, function (err2, data) {
                    if (err2) {
                        client.close();
                        console.log("ERROR in delete /account cognito adminDeleteUser");
                        console.log(err2.message, err2.code);
                        client.close();
                        res.status(500).render('error', { error: err2 });
                        return;
                    } else {
                        client.db("projetkhiron").collection("accounts").deleteOne({ _id: new ObjectID(_id) })
                            .then(result => {
                                res.status(200).send('Ok');
                            })
                            .catch(error => {
                                console.log("ERROR in delete /account mongodb deleteOne");
                                console.log(error.message, error.code);
                                res.status(500);
                                res.render('error', { error: error });
                            })
                            .finally(() => {
                                client.close();
                            });
                    }
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/roles', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.query.name && req.query.name.trim().length > 0) {
                query = { name: req.query.name.trim() }
            }

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /roles mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("groups").find(query).toArray(function (err2, result) {
                    if (err2) {
                        console.log("ERROR in get /roles mongodb find");
                        console.log(err2.message, err2.code);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/roles', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /roles mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                var tenant = "projetkhiron";
                if (req.headers.tenant && req.headers.tenant.length > 0) {
                    tenant = req.headers.tenant;
                }
                let searchID = new ObjectID(req.body._id);
                delete req.body._id;
                client.db(tenant).collection("groups").replaceOne({ _id: searchID }, req.body)
                    .then(result => {
                        res.json(result);
                    })
                    .catch(error => {
                        console.log("ERROR in put /roles mongodb replaceOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/roles/settings', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.body.name && req.body.name.trim().length > 0) {
                query = { name: req.body.name.trim() }
            }

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /roles/settings mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }


                client.db(tenant).collection("groups").updateOne(query, { $set: { settings: req.body.settings } }, { upsert: false })
                    .then(result => {
                        res.json(result);
                    })
                    .catch(error => {
                        console.log("ERROR in put /roles/settings mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/roles/options', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.body.name && req.body.name.trim().length > 0) {
                query = { name: req.body.name.trim() }
            }

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /roles/options mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("groups").updateOne(query, { $set: { label: req.body.label, "settings.options": req.body.options } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /roles/options mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/heartbeat', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            let query = {};
            if (req.body.userId && req.body.userId.trim().length > 0) {
                query = { _id: new ObjectID(req.body.userId.trim()) }
            }
            var statusDevice = 'unknown';
            if (req.body.statusDevice && req.body.statusDevice.trim().length > 0) {
                statusDevice = req.body.statusDevice;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /heartbeat mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db("projetkhiron").collection("accounts").updateOne(query, { $set: { lastSeen: new Date(req.body.date), status: req.body.status, statusDevice: statusDevice } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /heartbeat mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/floors', function (req, res, next) {
    //TODO:need access token for public requests

    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    var tenant = "projetkhiron";
    if (req.headers.tenant && req.headers.tenant.length > 0) {
        tenant = req.headers.tenant;
    }
    client.connect(err => {
        if (err) {
            client.close();
            console.log("ERROR in get /floors mongodb connect");
            console.log(err.message, err.code);
            res.status(500);
            res.render('error', { error: err });
            return;
        }
        client.db(tenant).collection("floors").find({}).sort({ label: 1 }).toArray(function (err2, result) {
            if (err2) {
                console.log("ERROR in get /floors mongodb find");
                console.log(err2.message, err2.code);
                res.status(500);
                res.render('error', { error: err2 });
            } else {
                res.json(result);
            }
            client.close();
        });
    });
});

router.get('/floor/:id', function (req, res, next) {
    //TODO:need access token verification for public requests
    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    var tenant = "projetkhiron";
    if (req.headers.tenant && req.headers.tenant.length > 0) {
        tenant = req.headers.tenant;
    }
    client.connect(err => {
        if (err) {
            client.close();
            console.log("ERROR in get /floor/:id mongodb connect");
            console.log(err.message, err.code);
            res.status(500);
            res.render('error', { error: err });
            return;
        }
        var o_id = new mongo.ObjectID(req.params.id);
        client.db(tenant).collection("floors").findOne({ _id: o_id })
            .then(result => {
                if (result)
                    res.json(result);
                else
                    res.json([]);
            })
            .catch(error => {
                console.log("ERROR in get /floor/:id mongodb findOne");
                console.log(error.message, error.code);
                res.status(500);
                res.render('error', { error: error });
            })
            .finally(() => {
                client.close();
            });
    });
});

router.delete('/floor/:id', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in delete /floor/:id mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                var o_id = new mongo.ObjectID(req.params.id);
                client.db(tenant).collection("floors").remove({ _id: o_id })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in delete /floor/:id mongodb remove");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/floor', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }
            if (req.body._id === "-1") { //new floor
                client.connect(err => {
                    if (err) {
                        client.close();
                        console.log("ERROR in put new /floor mongodb connect");
                        console.log(err.message, err.code);
                        res.status(500);
                        res.render('error', { error: err });
                        return;
                    }
                    delete req.body._id;
                    client.db(tenant).collection("floors").insertOne(req.body)
                        .then(result => {
                            res.status(200).json({ insertedId: result.insertedId });
                        })
                        .catch(error => {
                            console.log("ERROR in put new /floor mongodb insertOne");
                            console.log(error.message, error.code);
                            res.status(500);
                            res.render('error', { error: error });
                        })
                        .finally(() => {
                            client.close();
                        });
                });
            } else {
                client.connect(err => {
                    if (err) {
                        client.close();
                        console.log("ERROR in put /floor mongodb connect");
                        console.log(err.message, err.code);
                        res.status(500);
                        res.render('error', { error: err });
                        return;
                    }
                    let searchID = new ObjectID(req.body._id);
                    delete req.body._id;
                    client.db(tenant).collection("floors").replaceOne({ _id: searchID }, req.body)
                        .then(result => {
                            res.status(200).send('Ok');
                        })
                        .catch(error => {
                            console.log("ERROR in put /floor mongodb replaceOne");
                            console.log(error.message, error.code);
                            res.status(500);
                            res.render('error', { error: error });
                        })
                        .finally(() => {
                            client.close();
                        });
                });
            }
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/beds/:id', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            //if(req.params.id && req.params.id.trim().length === 12 ) { //ObjectId is a single String of 12 bytes, anything else means a uuid for a new object.
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /beds/:id mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("beds").findOne({ parent: req.params.id })
                    .then(result => {
                        if (result)
                            res.json(result.beds);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        console.log("ERROR in get /beds/:id mongodb findOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
            // } else {
            //     res.status(200).send('Ok');
            // }
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/bearer/requests', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.query.from && req.query.from.trim().length > 0 && !req.query.to) {
                query = {
                    requestedOn: {
                        $gte: new Date(req.query.from)
                    }
                }
            } else if (req.query.from && req.query.from.trim().length > 0 && req.query.to && req.query.to.trim().length > 0) {
                query = {
                    requestedOn: {
                        $gte: new Date(req.query.from),
                        $lte: new Date(req.query.to)
                    }
                }
            }
            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /bearer/requests mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("bearerRequests").find(query).sort({ requestedOn: -1 }).toArray(function (err2, result) {
                    if (err2) {
                        console.log("ERROR in get /bearer/requests mongodb find");
                        console.log(err2.message, err2.code);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/cleaner/requests', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            let query = {};
            if (req.query.from && req.query.from.trim().length > 0 && !req.query.to) {
                query = {
                    requestedOn: {
                        $gte: new Date(req.query.from)
                    }
                }
            } else if (req.query.from && req.query.from.trim().length > 0 && req.query.to && req.query.to.trim().length > 0) {
                query = {
                    requestedOn: {
                        $gte: new Date(req.query.from),
                        $lte: new Date(req.query.to)
                    }
                }
            }
            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }
            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /cleaner/requests mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("cleanerRequests").find(query).sort({ requestedOn: -1 }).toArray(function (err2, result) {
                    if (err2) {
                        console.log("ERROR in get /cleaner/requests mongodb find");
                        console.log(err2.message, err2.code);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/bearer/requests/stats', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /bearer/requests/stats mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("bearerRequestsStats").findOne({ type: req.query.type })
                    .then(result => {
                        if (result)
                            res.json(result.data);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        console.log("ERROR in get /bearer/requests/stats mongodb findOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/cleaner/requests/stats', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /cleaner/requests/stats mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("cleanerRequestsStats").findOne({ type: req.query.type })
                    .then(result => {
                        if (result)
                            res.json(result.data);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        console.log("ERROR in get /cleaner/requests/stats mongodb findOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});


const getBearerToAssignNewRequest = (req) => {
    return new Promise((resolve, reject) => {
       // need consider :
       //    sector assignments
       //    options assigned to bearers
       // Round-Robin or Notify-Accept Algorithm

                    resolve(true);
                    //reject()
       
    });
}

router.put('/bearer/request', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            if (req.headers.tenant && req.headers.tenant.length > 0){ 
                const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
                var tenant = req.headers.tenant;

                client.connect(err => {
                    if (err) {
                        client.close();
                        console.log("ERROR in put /bearer/request mongodb connect");
                        console.log(err.message, err.code);
                        res.status(500);
                        res.render('error', { error: err });
                        return;
                    }

                    client.db(tenant).collection("systemSettings").find({ config: "production" }).toArray(function (err2, settings) {
                        if (err2) {
                            client.close();
                            console.log("ERROR in put /bearer/request mongodb find");
                            console.log(err2.message, err2.code);
                            res.status(500);
                            res.render('error', { error: err2 });
                        } else {
                            const { from, to, requestedOn, options } = req.body;

                            client.db(tenant).collection("bearerRequests").insertOne({ _id: new ObjectID(), from, to, options: options, assigned: null, requestedOn: new Date(requestedOn), assignedOn: new Date(0), completedOn: new Date(0) })
                                .then(result => {
                                    let notifMasg = {
                                        "default": "Default Demande de Brancarderie",
                                        "APNS_SANDBOX": "{\"aps\" : {\"content-available\":1}, \"type\":\"bearer\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Brancarderie\",\"body\" : \"De " + from.label + " vers " + to.label + "\"}",
                                        "APNS": "{\"aps\" : {\"content-available\":1}, \"type\":\"bearer\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Brancarderie\",\"body\" : \"De " + from.label + " vers " + to.label + "\"}",
                                        "GCM": "{ \"data\": { \"type\":\"bearer\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Brancarderie\",\"body\" : \"De " + from.label + " vers " + to.label + "\"} }",
                                    };
                                    var params = {
                                        Message: JSON.stringify(notifMasg),
                                        MessageStructure: 'json',
                                        TopicArn: settings[0].notif.bearer,
                                    };

                                    // Create promise and SNS service object
                                    var publishTextPromise = new AWS.SNS().publish(params).promise();

                                    // Handle promise's fulfilled/rejected states
                                    publishTextPromise.then(
                                        function (data) {
                                            res.status(200).send('Ok');
                                        }).catch(error => {
                                            console.log("ERROR in put /bearer/request SNS publish");
                                            console.log(error.message, error.code);
                                            res.status(500);
                                            res.render('error', { error: error });
                                        });
                                })
                                .catch(error => {
                                    console.log("ERROR in put /bearer/request mongodb insertOne");
                                    console.log(error.message, error.code);
                                    res.status(500);
                                    res.render('error', { error: error });
                                }).finally(() => {
                                    client.close();
                                });
                        }
                    });
                });
            } else {
                res.status(403);
                res.render('error', { error: { message: 'Access denied', code: 403 } });
            }
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/cleaner/request', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /cleaner/request mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("systemSettings").find({ config: "production" }).toArray(function (err2, settings) {
                    if (err2) {
                        console.log("ERROR in put /cleaner/request mongodb find");
                        console.log(err2.message, err2.code);
                        client.close();
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        const { from, requestedOn, options } = req.body;

                        client.db(tenant).collection("cleanerRequests").insertOne({ _id: new ObjectID(), from, options: options, assigned: null, requestedOn: new Date(requestedOn), assignedOn: new Date(0), completedOn: new Date(0) })
                            .then(result => {
                                let notifMasg = {
                                    "default": "Default Demande de Nettoyage et salubrité",
                                    "APNS_SANDBOX": "{\"aps\":{\"content-available\":1},\"type\":\"cleaner\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Nettoyage & salubrité\",\"body\":\"Pour " + from.label + "\"}",
                                    "APNS": "{\"aps\":{\"content-available\":1},\"type\":\"cleaner\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Nettoyage & salubrité\",\"body\":\"Pour " + from.label + "\"}",
                                    "GCM": "{ \"data\": { \"type\":\"cleaner\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Nettoyage & salubrité\",\"body\":\"Pour " + from.label + "\"} }",
                                };
                                var params = {
                                    Message: JSON.stringify(notifMasg),
                                    MessageStructure: 'json',
                                    TopicArn: settings[0].notif.cleaner,
                                };

                                // Create promise and SNS service object
                                var publishTextPromise = new AWS.SNS().publish(params).promise();

                                // Handle promise's fulfilled/rejected states
                                publishTextPromise.then(
                                    function (data) {
                                        res.status(200).send('Ok');
                                    }).catch(error => {
                                        console.log("ERROR in put /cleaner/request SNS publish");
                                        console.log(error.message, error.code);
                                        res.status(500);
                                        res.render('error', { error: error });
                                    });
                            })
                            .catch(error => {
                                console.log("ERROR in put /cleaner/request mongodb insertOne");
                                console.log(error.message, error.code);
                                res.status(500);
                                res.render('error', { error: error });
                            }).finally(() => {
                                client.close();
                            });
                    }
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/bearer/request/accept', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            const { requestId, userId, userLabel, assignedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /bearer/request/acceptt mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("bearerRequests").updateOne(query, { $set: { assigned: { _id: new ObjectID(userId), label: userLabel }, assignedOn: new Date(assignedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /bearer/request/acceptt mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/serviceLevel', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            const { serviceLevel, forGroup } = req.body;

            let query = { name: forGroup };

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /serviceLevel mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("groups").updateOne(query, { $set: { "settings.serviceLevel": serviceLevel } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /serviceLevel mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/cleaner/request/accept', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            const { requestId, userId, userLabel, assignedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /cleaner/request/accept mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("cleanerRequests").updateOne(query, { $set: { assigned: { _id: new ObjectID(userId), label: userLabel }, assignedOn: new Date(assignedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /cleaner/request/accept mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/bearer/request/completed', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            const { requestId, completedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /bearer/request/completed mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("bearerRequests").updateOne(query, { $set: { completedOn: new Date(completedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /bearer/request/completed mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/cleaner/request/completed', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            const { requestId, completedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /cleaner/request/completedd mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("cleanerRequests").updateOne(query, { $set: { completedOn: new Date(completedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /cleaner/request/completedd mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/settings', function (req, res, next) {
    //TODO:need access token
    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

    let query = {};
    if (req.query.config && req.query.config.trim().length > 0) {
        query = { config: req.query.config.trim() }
    }

    var tenant = "projetkhiron";
    if (req.headers.tenant && req.headers.tenant.length > 0) {
        tenant = req.headers.tenant;
    }

    client.connect(err => {
        if (err) {
            client.close();
            console.log("ERROR in get /settings mongodb connect");
            console.log(err.message, err.code);
            res.status(500);
            res.render('error', { error: err });
            return;
        }
        client.db(tenant).collection("systemSettings").find(query).toArray(function (err2, result) {
            if (err2) {
                console.log("ERROR in get /settings mongodb find");
                console.log(err2.message, err2.code);
                res.status(500);
                res.render('error', { error: err2 });
            } else {
                res.json(result);
            }
            client.close();
        });
    });
});

router.post('/settings/licence', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (req.headers.tenant && req.headers.tenant.length > 0) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.body.config && req.body.config.trim().length > 0) {
                query = { config: req.body.config.trim() }
            }
            var tenant = req.headers.tenant;

            if(req.body.licence){
                readLicence(req.body.licence).then(data => {
                    var txtDecoder = new TextDecoder();
                    const dataMsg = nacl.util.decodeBase64(data);
                    const publicKey = nacl.util.decodeBase64(config.licence.pubKey);
                    const licenceJson = nacl.sign.open(dataMsg, publicKey);
                    res.json(JSON.parse(txtDecoder.decode(licenceJson)));
                }).catch(err => {
                    res.status(500);
                    res.render('error', { error: err });
                })
            } else {
                client.connect(err => {
                    if (err) {
                        client.close();
                        console.log("ERROR in get /settings/licence mongodb connect");
                        console.log(err.message, err.code);
                        res.status(500);
                        res.render('error', { error: err });
                        return;
                    }
                    client.db(tenant).collection("systemSettings").find(query).toArray(function (err2, result) {
                        if (err2) {
                            console.log("ERROR in get /settings/licence mongodb find");
                            console.log(err2.message, err2.code);
                            res.status(500);
                            res.render('error', { error: err2 });
                        } else {
                            var licenceString = result[0].licence;
                            readLicence(licenceString).then(data => {
                                var txtDecoder = new TextDecoder();
                                const dataMsg = nacl.util.decodeBase64(data);
                                const publicKey = nacl.util.decodeBase64(config.licence.pubKey);
                                const licenceJson = nacl.sign.open(dataMsg, publicKey);
                                res.json(JSON.parse(txtDecoder.decode(licenceJson)));
                            }).catch(err => {
                                res.status(500);
                                res.render('error', { error: err });
                            })
                        }
                        client.close();
                    });
                });
            }
        } else {
            res.status(404);
            res.render('error', { error: {message:'not found', code:404}});
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

async function readLicence(licenceFile) {
    var buf = new Buffer.from(licenceFile.replace(" ", "\r\n"));
    
    var bufferStream = new stream.PassThrough();
    bufferStream.end(buf);
    
    var rl = readline.createInterface({
        input: bufferStream,
        crlfDelay: Infinity
    });

    var sb = [];
    for await (const line of rl) {
        if(line !== "====================-LICENCE-START-====================" && line !== "====================--LICENCE-END--====================")
            sb.push(line);
    }
    return sb.join("");
}

router.put('/settings', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            const { settings } = req.body;

            let query = { _id: new ObjectID(settings._id) };
            delete settings._id;

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /settings mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("systemSettings").replaceOne(query, settings, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /settings mongodb replaceOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/bearer/analysis', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            var MS_PER_MINUTE = 60000;

            if (req.query.type === "outOfService") {
                var beforeDate = new Date(new Date().getTime() - (parseInt(req.query.seviceLevel) * MS_PER_MINUTE));

                query = { requestedOn: { $lte: beforeDate }, completedOn: { $eq: new Date(0) } }
            }

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /bearer/analysiss mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("bearerRequests").find(query).sort({ requestedOn: 1 }).toArray(function (err2, result) {
                    if (err2) {
                        console.log("ERROR in get /bearer/analysiss mongodb find");
                        console.log(err2.message, err2.code);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/cleaner/analysis', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            var MS_PER_MINUTE = 60000;

            if (req.query.type === "outOfService") {
                var beforeDate = new Date(new Date().getTime() - (parseInt(req.query.seviceLevel) * MS_PER_MINUTE));

                query = { requestedOn: { $lte: beforeDate }, completedOn: { $eq: new Date(0) } }
            }

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /cleaner/analysiss mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("cleanerRequests").find(query).sort({ requestedOn: 1 }).toArray(function (err2, result) {
                    if (err2) {
                        console.log("ERROR in get /cleaner/analysiss mongodb find");
                        console.log(err2.message, err2.code);
                        res.status(500);
                        res.render('error', { error: err });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/visitor/requests', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            let query = {};
            if (req.query.from && req.query.from.trim().length > 0 && !req.query.to) {
                query = {
                    requestedOn: {
                        $gte: new Date(req.query.from)
                    }
                }
            } else if (req.query.from && req.query.from.trim().length > 0 && req.query.to && req.query.to.trim().length > 0) {
                query = {
                    requestedOn: {
                        $gte: new Date(req.query.from),
                        $lte: new Date(req.query.to)
                    }
                }
            }

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /visitor/requests mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("visitorRequests").find(query).sort({ requestedOn: -1 }).toArray(function (err2, result) {
                    if (err2) {
                        console.log("ERROR in get /visitor/requests mongodb find");
                        console.log(err2.message, err2.code);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/visitor/requests', function (req, res, next) {
    //TODO:need access token
    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

    var tenant = "projetkhiron";
    if (req.headers.tenant && req.headers.tenant.length > 0) {
        tenant = req.headers.tenant;
    }

    client.connect(err => {
        if (err) {
            client.close();
            console.log("ERROR in put /visitor/requests mongodb connect");
            console.log(err.message, err.code);
            res.status(500);
            res.render('error', { error: err });
            return;
        }

        const { requestFor, requestedOn, options } = req.body;

        client.db(tenant).collection("visitorRequests").insertOne({ _id: new ObjectID(), requestFor: requestFor, requestedOn: new Date(requestedOn), options: options })
            .then(result => {
                res.status(200).send('Ok');
            })
            .catch(error => {
                console.log("ERROR in get /visitor/requests mongodb insertOne");
                console.log(error.message, error.code);
                res.status(500);
                res.render('error', { error: error });
            })
            .finally(() => {
                client.close();
            });
    });
});

router.get('/visitor/requests/stats', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in get /visitor/requests/stats mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(tenant).collection("visitorRequestsStats").findOne({ type: req.query.type })
                    .then(result => {
                        if (result)
                            res.json(result.data);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        console.log("ERROR in get /visitor/requests/stats mongodb findOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.put('/visitor/settings', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            let query = { config: "production" }

            client.connect(err => {
                if (err) {
                    client.close();
                    console.log("ERROR in put /visitor/settings mongodb connect");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(tenant).collection("systemSettings").updateOne(query, { $set: { "visitor.settings": req.body.settings } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        console.log("ERROR in put /visitor/settings mongodb updateOne");
                        console.log(error.message, error.code);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});

router.get('/visitor/settings', function (req, res, next) {
    //TODO:naccess token
    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    if (req.headers.tenant && req.headers.tenant.length > 0) {
        var tenant = req.headers.tenant;
        let query = { config: "production" }

        client.connect(err => {
            if (err) {
                client.close();
                console.log("ERROR in get /visitor/settings mongodb connect");
                console.log(err.message, err.code);
                res.status(500);
                res.render('error', { error: err });
                return;
            }
            client.db(tenant).collection("systemSettings").find(query).toArray(function (err2, result) {
                if (err2) {
                    console.log("ERROR in get /visitor/settings mongodb find");
                    console.log(err2.message, err2.code);
                    res.status(500);
                    res.render('error', { error: err2 });
                } else {
                    if(result && result.length > 0) {
                        res.json({ settings: { ...result[0].visitor.settings } });
                    } else {
                        res.status(404);
                        res.render('error', { error: {message:'not found', code:404}});
                    }
                }
                client.close();
            })
        });
    } else {
        res.status(404);
        res.render('error', { error: {message:'not found', code:404}});
    }
});

const generateInitialSearchPipeline = (options) => {
    var pipelineStages = [];
    var shouldTextSearch = [];
    options.forEach(opt => {
        //var opt = JSON.parse(stringOption);
        if (opt.type === "string" && opt.value && opt.value.trim().length > 0) {
            if(opt.entity && opt.entity === "name") {
                shouldTextSearch.push({
                    "text": {
                        "query": opt.value,
                        "path": "options.value",
                        "fuzzy": {}
                    }
                });
            } 
        }
    });
    if (shouldTextSearch.length == 1) {
        pipelineStages.push({
            $search: {
                "index": 'default', // optional, defaults to "default"
                ...shouldTextSearch[0]
            }
        });
    } else if (shouldTextSearch.length > 1) {
        pipelineStages.push({
            $search: {
                "index": 'default', // optional, defaults to "default"
                "compound": {
                    "must": shouldTextSearch
                }
            }
        });
    }
    options.forEach(opt => {
        if(opt.type === "static-list") {
            if(opt.multi)
                pipelineStages.push({ $match: { "options._id": opt._id,  "options.valueId": { $all:  opt.value } }});
            else
                pipelineStages.push({ $match: { "options._id": opt._id, "options.valueId": opt.value } });
        } else if (((opt.type === "string" && opt.entity !== "name") || opt.type === "numeric") && opt.value.trim().length>0) {
            pipelineStages.push({ $match: { "options._id": opt._id, "options.valueId": opt.value } });
        } else if (opt.type === "telephone" && opt.value.trim().length===13) {
            pipelineStages.push({ $match: { "options._id": opt._id, "options.valueId": opt.value } });
        } else if(opt.entity !== "name" && opt.value.trim().length>0) { //yes/no, email
            pipelineStages.push({ $match: { "options._id": opt._id, "options.valueId": opt.value } });
        }
    });
    return pipelineStages;
}

router.post('/requests/search', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        if (isAuthorized) {
            var tenant = "projetkhiron";
            if (req.headers.tenant && req.headers.tenant.length > 0) {
                tenant = req.headers.tenant;
            }

            const { floorID, sectionID, bedID, visitorOptions, bearerOptions, cleanerOptions, fromDate, toDate, searchVisitor, searchBearer, searchCleaner } = req.body;

            (async () => {
                let client = await MongoClient.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

                var promises = []

                var currentPromiseIdx = -1;
                var visitorPromiseIdx = -1;
                var bearerPromiseIdx = -1;
                var cleanerPromiseIdx = -1;

                if (searchVisitor) {
                    let visitorPipelineStages = [];
                    if (visitorOptions) {
                        //first stage of pipeline has to be $search if there is any
                        visitorPipelineStages = generateInitialSearchPipeline(visitorOptions);
                    }

                    if (bedID) {
                        visitorPipelineStages.push({ $match: { "requestFor.type": "bed", "requestFor._id": bedID } });
                    } else if (sectionID) {
                        visitorPipelineStages.push({ $match: { "requestFor.section._id": sectionID } });
                    } else if (floorID) {
                        visitorPipelineStages.push({ $match: { "requestFor.section.floorID": floorID } });
                    }

                    visitorPipelineStages.push({ $match: { requestedOn: { $lte: new Date(toDate), $gte: new Date(fromDate) } } });

                    promises.push(client.db(tenant).collection("visitorRequests").aggregate(visitorPipelineStages).toArray());

                    currentPromiseIdx = currentPromiseIdx + 1;
                    visitorPromiseIdx = currentPromiseIdx;
                }

                if (searchBearer) {
                    let bearerPipelineStages = [];
                    if (bearerOptions) {
                        //first stage of pipeline has to be $search if there is any
                        bearerPipelineStages = generateInitialSearchPipeline(bearerOptions);
                    }

                    if (bedID) {
                        bearerPipelineStages.push({ $match: { $or: [{ "from.type": "bed", "from._id": bedID }, { "to.type": "bed", "to._id": bedID }] } });
                    } else if (sectionID) {
                        bearerPipelineStages.push({
                            $match: {
                                $or: [
                                    { "from.type": "bed", "from.section._id": sectionID }, { "to.type": "bed", "to.section._id": sectionID },
                                    { "from.type": "section", "from._id": sectionID }, { "to.type": "section", "to._id": sectionID }
                                ]
                            }
                        });
                    } else if (floorID) {
                        bearerPipelineStages.push({
                            $match: {
                                $or: [
                                    { "from.type": "bed", "from.section.floorID": floorID }, { "to.type": "bed", "to.section.floorID": floorID },
                                    { "from.type": "section", "from.floorID": floorID }, { "to.type": "section", "to.floorID": floorID },
                                    { "from.type": "floor", "from._id": floorID }, { "to.type": "floor", "to._id": floorID },
                                ]
                            }
                        });
                    }

                    bearerPipelineStages.push({ $match: { completedOn: { $lte: new Date(toDate), $gte: new Date(fromDate) } } });

                    promises.push(client.db(tenant).collection("bearerRequests").aggregate(bearerPipelineStages).toArray());

                    currentPromiseIdx = currentPromiseIdx + 1;
                    bearerPromiseIdx = currentPromiseIdx;
                }

                if (searchCleaner) {
                    let cleanerPipelineStages = [];
                    if (cleanerOptions) {
                        //first stage of pipeline has to be $search if there is any
                        cleanerPipelineStages = generateInitialSearchPipeline(cleanerOptions);
                    }

                    if (bedID) {
                        cleanerPipelineStages.push({ $match: { "from.type": "bed", "from._id": bedID } });
                    } else if (sectionID) {
                        cleanerPipelineStages.push({
                            $match: {
                                $or: [
                                    { "from.type": "bed", "from.section._id": sectionID },
                                    { "from.type": "section", "from._id": sectionID }
                                ]
                            }
                        });
                    } else if (floorID) {
                        cleanerPipelineStages.push({
                            $match: {
                                $or: [
                                    { "from.type": "bed", "from.section.floorID": floorID },
                                    { "from.type": "section", "from.floorID": floorID },
                                    { "from.type": "floor", "from._id": floorID }
                                ]
                            }
                        });
                    }

                    cleanerPipelineStages.push({ $match: { completedOn: { $lte: new Date(toDate), $gte: new Date(fromDate) } } });

                    promises.push(client.db(tenant).collection("cleanerRequests").aggregate(cleanerPipelineStages).toArray());

                    currentPromiseIdx = currentPromiseIdx + 1;
                    cleanerPromiseIdx = currentPromiseIdx;
                }

                Promise.all(promises).then((values) => {
                    var events = [];
                    if (visitorPromiseIdx !== -1) {
                        values[visitorPromiseIdx].forEach(request => {
                            events.push({ _id: request._id, date: request.requestedOn, type: 'visitor', options: [{ _id: request._id + "-1", label: "Visité lit", value: request.requestFor.label }, ...request.options] });
                        });
                    }

                    if (bearerPromiseIdx !== -1) {
                        values[bearerPromiseIdx].forEach(request => {
                            var localOptions = [];
                            if (request.from)
                                localOptions.push({ _id: request.from._id+"-from", label: "Déplacement de", value: request.from.label });
                            if (request.to)
                                localOptions.push({ _id: request.to._id+"-to", label: "Vers", value: request.to.label });
                            if (request.assigned)
                                localOptions.push({ _id: request.assigned._id, label: "Brancardier", value: request.assigned.label });
                            events.push({ _id: request._id, date: request.completedOn, type: 'bearer', options: [...localOptions, ...request.options] });
                        });
                    }

                    if (cleanerPromiseIdx !== -1) {
                        values[cleanerPromiseIdx].forEach(request => {
                            var localOptions = [];
                            if (request.from)
                                localOptions.push({ _id: request.from._id, label: "Nettoyé lit", value: request.from.label });
                            if (request.assigned)
                                localOptions.push({ _id: request.assigned._id, label: "Nettoyeure", value: request.assigned.label });
                            events.push({ _id: request._id, date: request.completedOn, type: 'cleaner', options: [...localOptions, ...request.options] });
                        });
                    }

                    var sortedEvents = [...events].sort(function eventDateCompare(a, b) {
                        if (a.date > b.date) {
                            return -1;
                        }
                        if (a.date < b.date) {
                            return 1;
                        }
                        return 0;
                    });
                    res.json(sortedEvents);
                }).catch(err => {
                    console.log("ERROR in get /requests/search");
                    console.log(err.message, err.code);
                    res.status(500);
                    res.render('error', { error: err });
                }).finally(() => {
                    client.close();
                })
            })()
                .catch(error => {
                    console.log("ERROR in get /requests/search");
                    console.log(error.message, error.code);
                    res.status(500);
                    res.render('error', { error: error });
                })
        } else {
            res.status(403);
            res.render('error', { error: { message: 'Access denied', code: 403 } });
        }
    }).catch(err => {
        res.status(403);
        res.render('error', { error: { message: 'Access denied', code: 403 } });
    })
});


module.exports = router;
