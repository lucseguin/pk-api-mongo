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
const DigestFetch = require('digest-fetch')
const { v4: uuidv4 } = require('uuid');

const MongoClient = mongo.MongoClient;
const ObjectID = mongo.ObjectID;

const config = require('../config')
const defaultdb = require('../defaultdb')

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

const DEFAULT_APPLICATION_DB = "projetkhiron";

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

const getSiteDetailsSiteID = (siteID) => {
    return new Promise((resolve, reject) => {
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        let searchID = new ObjectID(siteID);
        client.connect().then(value => {
            client.db("projetkhiron").collection("sites").find({_id:searchID}).toArray().then(result => {
                if(result.length === 0)
                    reject(new Error("Site not found"));
                else
                    resolve(result[0]);
            }).catch(err => {
                reject(err2);
            }).finally(() => {
                client.close();
            });
        }).catch(err => {
            reject(err);
        });
    });
}

async function insertErrorLog(siteDetails, err) {
    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    client.connect().then(connected => {
        var error = '';
        if(err.stack)
            error = err.stack;
        else 
            error = err.toString();
        client.db("projetkhiron").collection("errorLogs").insertOne({ _id: new ObjectID(), on:new Date(), forSite:siteDetails.db, error:error}).then(result => {
            
        }).catch(err2 => {
            console.log(err2);
        }).finally(() => {
            client.close();
        });
    }).catch(error => {
        console.log(error);
    })
}

/* GET users listing. */
router.get('/accounts', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            
            let query = {"sites._id":siteDetails._id.toString()};

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db("projetkhiron").collection("accounts").find(query).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: { message: "Missing parameter", code: 400 } });
        })
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: { message: 'Access not authorized', code: 403 } });
    })
});

router.get('/accounts/:role', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                let query = { "role.name": req.params.role , "sites._id": siteDetails._id.toString()};

                client.db("projetkhiron").collection("accounts").find(query).toArray()
                    .then(accounts => {
                        if (accounts)
                            res.json(accounts);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: { message: "Missing parameter", code: 400 } });
        })
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: { message: 'Access not authorized', code: 403 } });
    })
});

router.get('/account', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        let query = {};

        if (req.query.email && req.query.email.trim().length > 0) {
            query = { ...query, email: req.query.email.trim() };

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db("projetkhiron").collection("accounts").find(query).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        } else {
            insertErrorLog(siteDetails, new Error("Missing email parameter") );
            res.status(400);
            res.render('error', { error: new Error("Missing email parameter") });
        }
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/account', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        //no need to get site details, accounts are org wide
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        client.connect(err => {
            if (err) {
                client.close();
                insertErrorLog(siteDetails,err);
                res.status(500);
                res.render('error', { error: err });
                return;
            }

            const { _id, firstName, lastName, role, email, phone, sites} = req.body;
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
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        client.db("projetkhiron").collection("accounts").insertOne({ _id: new ObjectID(), cognitoID: data.User.Username, status: 'offline', statusDevice: 'unknown', lastSeen: new Date(), firstName: firstName, lastName: lastName, role: role, email: email, phone: phone, properties: [], paletteType: 'dark', sites:sites })
                            .then(result => {
                                res.status(200).send('Ok');
                            })
                            .catch(error => {
                                insertErrorLog(siteDetails,error);
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
                client.db("projetkhiron").collection("accounts").updateOne(query, { $set: { firstName: firstName, lastName: lastName, role: role, phone: phone, sites:sites } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            }
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: { message: 'Access not authorized', code: 403 } });
    })
});

router.delete('/account', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        //no need to get site details, accounts are org wide
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        client.connect(err => {
            if (err) {
                client.close();
                insertErrorLog(siteDetails,err);
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
                    insertErrorLog(siteDetails,err2);
                    client.close();
                    res.status(500).render('error', { error: err2 });
                    return;
                } else {
                    client.db("projetkhiron").collection("accounts").deleteOne({ _id: new ObjectID(_id) })
                        .then(result => {
                            res.status(200).send('Ok');
                        })
                        .catch(error => {
                            insertErrorLog(siteDetails,error);
                            res.status(500);
                            res.render('error', { error: error });
                        })
                        .finally(() => {
                            client.close();
                        });
                }
            });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: { message: 'Access not authorized', code: 403 } });
    })
});

router.get('/roles', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.query.name && req.query.name.trim().length > 0) {
                query = { name: req.query.name.trim() }
            } else {
                query = {hidden:false};
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("groups").find(query).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/roles', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                let searchID = new ObjectID(req.body._id);
                delete req.body._id;
                client.db(siteDetails.db).collection("groups").replaceOne({ _id: searchID }, req.body)
                    .then(result => {
                        res.json(result);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/roles/settings', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.body.name && req.body.name.trim().length > 0) {
                query = { name: req.body.name.trim() }
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("groups").updateOne(query, { $set: { settings: req.body.settings } }, { upsert: false })
                    .then(result => {
                        res.json(result);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/roles/options', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            if (req.body.name && req.body.name.trim().length > 0) {
                query = { name: req.body.name.trim() }
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("groups").updateOne(query, { $set: { label: req.body.label, "settings.options": req.body.options } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/heartbeat', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        //no need to get site details, accounts are org wide
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
                insertErrorLog(siteDetails,err);
                res.status(500);
                res.render('error', { error: err });
                return;
            }
            client.db("projetkhiron").collection("accounts").updateOne(query, { $set: { lastSeen: new Date(req.body.date), status: req.body.status, statusDevice: statusDevice } }, { upsert: false })
                .then(result => {
                    res.status(200).send('Ok');
                })
                .catch(error => {
                    insertErrorLog(siteDetails,error);
                    res.status(500);
                    res.render('error', { error: error });
                })
                .finally(() => {
                    client.close();
                });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/floors', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("floors").find({}).sort({ label: 1 }).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/floor/:id', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                var o_id = new mongo.ObjectID(req.params.id);
                client.db(siteDetails.db).collection("floors").findOne({ _id: o_id })
                    .then(result => {
                        if (result)
                            res.json(result);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.delete('/floor/:id', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                var o_id = new mongo.ObjectID(req.params.id);
                client.db(siteDetails.db).collection("floors").remove({ _id: o_id })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/floor', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            if (req.body._id === "-1") { //new floor
                client.connect(err => {
                    if (err) {
                        client.close();
                        insertErrorLog(siteDetails,err);
                        res.status(500);
                        res.render('error', { error: err });
                        return;
                    }
                    delete req.body._id;
                    client.db(siteDetails.db).collection("floors").insertOne(req.body)
                        .then(result => {
                            res.status(200).json({ insertedId: result.insertedId });
                        })
                        .catch(error => {
                            insertErrorLog(siteDetails,error);
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
                        insertErrorLog(siteDetails,err);
                        res.status(500);
                        res.render('error', { error: err });
                        return;
                    }
                    let searchID = new ObjectID(req.body._id);
                    delete req.body._id;
                    client.db(siteDetails.db).collection("floors").replaceOne({ _id: searchID }, req.body)
                        .then(result => {
                            res.status(200).send('Ok');
                        })
                        .catch(error => {
                            insertErrorLog(siteDetails,error);
                            res.status(500);
                            res.render('error', { error: error });
                        })
                        .finally(() => {
                            client.close();
                        });
                });
            }
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/beds/:id', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("beds").findOne({ parent: req.params.id })
                    .then(result => {
                        if (result)
                            res.json(result.beds);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/bearer/requests', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
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

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("bearerRequests").find(query).sort({ requestedOn: -1 }).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog(siteDetails,err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog(siteDetails,err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/cleaner/requests', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
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

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("cleanerRequests").find(query).sort({ requestedOn: -1 }).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/bearer/requests/stats', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("bearerRequestsStats").findOne({ type: req.query.type })
                    .then(result => {
                        if (result)
                            res.json(result.data);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error:err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/cleaner/requests/stats', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("cleanerRequestsStats").findOne({ type: req.query.type })
                    .then(result => {
                        if (result)
                            res.json(result.data);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
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
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                getModuleSettingsForSite(siteDetails, "config").then(mergedSettings => {
                    const { from, to, requestedOn, options } = req.body;
                    client.db(siteDetails.db).collection("bearerRequests").insertOne({ _id: new ObjectID(), from, to, options: options, assigned: null, requestedOn: new Date(requestedOn), assignedOn: new Date(0), completedOn: new Date(0) }).then(result => {
                        let notifMasg = {
                            "default": "Default Demande de Brancarderie",
                            "APNS_SANDBOX": "{\"aps\" : {\"content-available\":1}, \"type\":\"bearer\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Brancarderie\",\"body\" : \"De " + from.label + " vers " + to.label + "\"}",
                            "APNS": "{\"aps\" : {\"content-available\":1}, \"type\":\"bearer\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Brancarderie\",\"body\" : \"De " + from.label + " vers " + to.label + "\"}",
                            "GCM": "{ \"data\": { \"type\":\"bearer\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Brancarderie\",\"body\" : \"De " + from.label + " vers " + to.label + "\"} }",
                        };
                        var params = {
                            Message: JSON.stringify(notifMasg),
                            MessageStructure: 'json',
                            TopicArn: mergedSettings.settings.notif.bearer,
                        };

                        // Create promise and SNS service object
                        var publishTextPromise = new AWS.SNS().publish(params).promise();

                        // Handle promise's fulfilled/rejected states
                        publishTextPromise.then(
                            function (data) {
                                res.status(200).send('Ok');
                            }).catch(error => {
                                insertErrorLog(siteDetails,error);
                                res.status(500);
                                res.render('error', { error: error });
                            });
                    }).catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                }).catch(error => {
                    insertErrorLog(siteDetails,error);
                    res.status(500);
                    res.render('error', { error: error });
                }).finally(() => {
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err});
    })
});

router.put('/cleaner/request', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                getModuleSettingsForSite(siteDetails, "config").then(mergedSettings => {
                    const { from, requestedOn, options } = req.body;
                    client.db(siteDetails.db).collection("cleanerRequests").insertOne({ _id: new ObjectID(), from, options: options, assigned: null, requestedOn: new Date(requestedOn), assignedOn: new Date(0), completedOn: new Date(0) }).then(result => {
                        let notifMasg = {
                            "default": "Default Demande de Nettoyage et salubrité",
                            "APNS_SANDBOX": "{\"aps\":{\"content-available\":1},\"type\":\"cleaner\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Nettoyage & salubrité\",\"body\":\"Pour " + from.label + "\"}",
                            "APNS": "{\"aps\":{\"content-available\":1},\"type\":\"cleaner\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Nettoyage & salubrité\",\"body\":\"Pour " + from.label + "\"}",
                            "GCM": "{ \"data\": { \"type\":\"cleaner\", \"tenant\":\"" + tenant + "\", \"title\" : \"Demande Nettoyage & salubrité\",\"body\":\"Pour " + from.label + "\"} }",
                        };
                        var params = {
                            Message: JSON.stringify(notifMasg),
                            MessageStructure: 'json',
                            TopicArn: mergedSettings.settings.notif.cleaner,
                        };

                        // Create promise and SNS service object
                        var publishTextPromise = new AWS.SNS().publish(params).promise();

                        // Handle promise's fulfilled/rejected states
                        publishTextPromise.then(
                            function (data) {
                                res.status(200).send('Ok');
                            }).catch(error => {
                                insertErrorLog(siteDetails,error);
                                res.status(500);
                                res.render('error', { error: error });
                            });
                    }).catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                }).catch(error => {
                    insertErrorLog(siteDetails,error);
                    res.status(500);
                    res.render('error', { error: error });
                }).finally(() => {
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/bearer/request/accept', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            const { requestId, userId, userLabel, assignedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("bearerRequests").updateOne(query, { $set: { assigned: { _id: new ObjectID(userId), label: userLabel }, assignedOn: new Date(assignedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/serviceLevel', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            const { serviceLevel, forGroup } = req.body;

            let query = { module: forGroup };

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("siteSettings").updateOne(query, { $set: { "settings.serviceLevel": serviceLevel } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/cleaner/request/accept', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            const { requestId, userId, userLabel, assignedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("cleanerRequests").updateOne(query, { $set: { assigned: { _id: new ObjectID(userId), label: userLabel }, assignedOn: new Date(assignedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/bearer/request/completed', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            const { requestId, completedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("bearerRequests").updateOne(query, { $set: { completedOn: new Date(completedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.put('/cleaner/request/completed', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            const { requestId, completedOn } = req.body;

            let query = { _id: new ObjectID(requestId) };

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }
                client.db(siteDetails.db).collection("cleanerRequests").updateOne(query, { $set: { completedOn: new Date(completedOn) } }, { upsert: false })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/sites', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        client.connect().then(value => {
            client.db(DEFAULT_APPLICATION_DB).collection("sites").find({}).toArray().then(values => {
                res.json(values);
            }).catch(error => {
                insertErrorLog({db:req.headers.site},error);
                res.status(500);
                res.render('error', { error: error });
            });
        }) .catch(error => {
            insertErrorLog({db:req.headers.site},error);
            res.status(500);
            res.render('error', { error: error });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err});
    });
});

router.put('/sites', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        const { db, label } = req.body;
        if(db && db.trim().length > 0 && label && label.trim().length > 0) {
            client.connect().then(value => {
                var createRequests = [];
                
                createRequests.push(client.db(db).createCollection("bearerRequests"));
                createRequests.push(client.db(db).createCollection("bearerRequestsStats"));
                createRequests.push(client.db(db).createCollection("beds"));
                createRequests.push(client.db(db).createCollection("cleanerRequests"));
                createRequests.push(client.db(db).createCollection("cleanerRequestsStats"));
                createRequests.push(client.db(db).createCollection("floors"));
                createRequests.push(client.db(db).createCollection("groups"));
                createRequests.push(client.db(db).createCollection("siteSettings"));
                createRequests.push(client.db(db).createCollection("visitorRequests"));
                createRequests.push(client.db(db).createCollection("visitorRequestsStats"));

                Promise.all(createRequests).then((createdCollections) => {
                    console.log("Collections Created")
                    var dataInserts = [];

                    dataInserts.push(client.db(db).collection("groups").insertMany([
                        { _id: new ObjectID(), ...defaultdb.groups.user},
                        { _id: new ObjectID(), ...defaultdb.groups.bearer},
                        { _id: new ObjectID(), ...defaultdb.groups.cleaner},
                        { _id: new ObjectID(), ...defaultdb.groups.admin},
                        { _id: new ObjectID(), ...defaultdb.groups.management},
                        { _id: new ObjectID(), ...defaultdb.groups.coodinator},
                        { _id: new ObjectID(), ...defaultdb.groups.sysadmin},
                     ]));

                    dataInserts.push(client.db(db).collection("bearerRequestsStats").insertMany([
                        { _id: new ObjectID(), type:'30-days', data:[]},
                        { _id: new ObjectID(), type:'7-days', data:[]}
                    ]));

                    dataInserts.push(client.db(db).collection("cleanerRequestsStats").insertMany([
                        { _id: new ObjectID(), type:'30-days', data:[]},
                        { _id: new ObjectID(), type:'7-days', data:[]}
                    ]));

                    dataInserts.push(client.db(db).collection("visitorRequestsStats").insertMany([
                        { _id: new ObjectID(), type:'30-days', data:[]},
                        { _id: new ObjectID(), type:'7-days', data:[]}
                    ]));

                    Promise.all(dataInserts).then((InsertedValues) => {
                        console.log("Default Data Inserted")

                        var indexCreation = [];

                        indexCreation.push(client.db(db).collection("siteSettings").createIndex({"module":1}));
                        indexCreation.push(client.db(db).collection("groups").createIndex({"name":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"options._id":1,"options.valueId":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"from._id":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"from.section._id":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"from.section.floorID":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"to._id":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"to.section._id":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"to.section.floorID":1}));
                        indexCreation.push(client.db(db).collection("bearerRequests").createIndex({"requestedOn":1}));
                        
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"options._id":1,"options.valueId":1}));
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"from._id":1}));
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"from.section._id":1}));
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"from.section.floorID":1}));
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"to._id":1}));
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"to.section._id":1}));
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"to.section.floorID":1}));
                        indexCreation.push(client.db(db).collection("cleanerRequests").createIndex({"requestedOn":1}));
                        
                        indexCreation.push(client.db(db).collection("visitorRequests").createIndex({"options._id":1,"options.valueId":1}));
                        indexCreation.push(client.db(db).collection("visitorRequests").createIndex({"requestFor._id":1}));
                        indexCreation.push(client.db(db).collection("visitorRequests").createIndex({"requestFor.section._id":1}));
                        indexCreation.push(client.db(db).collection("visitorRequests").createIndex({"requestFor.section.floorID":1}));
                        indexCreation.push(client.db(db).collection("visitorRequests").createIndex({"requestedOn":1}));
                        
                        Promise.all(indexCreation).then((indexCreated) => {
                            console.log("Indexes Created")
                            var sns = new AWS.SNS();
                            var bearerTopicArn = '';
                            var cleanerTopicArn = '';
                            sns.createTopic({ Name: 'ProjetKhiron-Bearer-Requests-'+db }, function(bearerErr, bearerData) {
                                if (bearerErr) {
                                    insertErrorLog({db:req.headers.site},bearerErr);
                                    res.status(500);
                                    res.render('error', { error: bearerErr });
                                } else {    
                                    bearerTopicArn = bearerData.TopicArn;
                                    sns.createTopic({ Name: 'ProjetKhiron-Cleaner-Requests-'+db }, function(cleanerErr, cleanerData) {
                                        if (cleanerErr) {
                                            insertErrorLog({db:req.headers.site},cleanerErr);
                                            res.status(500);
                                            res.render('error', { error: cleanerErr });
                                        } else {    
                                            cleanerTopicArn = cleanerData.TopicArn;
                                            client.db(db).collection("siteSettings").insertMany([
                                                { _id: new ObjectID(), ...defaultdb.settings.cleaner},
                                                { _id: new ObjectID(), ...defaultdb.settings.bearer},
                                                { _id: new ObjectID(), ...defaultdb.settings.visitor, setting:{ request: { properties: [] }, apikey:uuidv4()}},
                                                { _id: new ObjectID(), ...defaultdb.settings.config, settings:{ notif:{
                                                    bearer: bearerTopicArn,
                                                    cleaner: cleanerTopicArn
                                                }}}
                                            ]).then(insertResults => {
                                                client.db(DEFAULT_APPLICATION_DB).collection("sites").insertOne({ _id: new ObjectID(), db:db, label: label}).then(result => {                                    
                                                    var searchIndexCreation = [];
                                                    
                                                    const digestClient = new DigestFetch(config.database.publicKey, config.database.privateKey);
                                                    searchIndexCreation.push(digestClient.fetch("https://cloud.mongodb.com/api/atlas/v1.0/groups/"+config.database.groupid+"/clusters/"+config.database.cluster+"/fts/indexes?pretty=true",{ method: 'POST', body: JSON.stringify({"collectionName": "visitorRequests","database": db ,"mappings": {"dynamic": false,"fields": {"options": {"fields": {"value": {"type": "string"}}, "type": "document"}}},"name": "default"}), headers: {'Content-Type': 'application/json'} }));
                                                    searchIndexCreation.push(digestClient.fetch("https://cloud.mongodb.com/api/atlas/v1.0/groups/"+config.database.groupid+"/clusters/"+config.database.cluster+"/fts/indexes?pretty=true",{ method: 'POST', body: JSON.stringify({"collectionName": "bearerRequests","database": db ,"mappings": {"dynamic": false,"fields": {"options": {"fields": {"value": {"type": "string"}}, "type": "document"}}},"name": "default"}), headers: {'Content-Type': 'application/json'} }));
                                                    searchIndexCreation.push(digestClient.fetch("https://cloud.mongodb.com/api/atlas/v1.0/groups/"+config.database.groupid+"/clusters/"+config.database.cluster+"/fts/indexes?pretty=true",{ method: 'POST', body: JSON.stringify({"collectionName": "cleanerRequests","database": db ,"mappings": {"dynamic": false,"fields": {"options": {"fields": {"value": {"type": "string"}}, "type": "document"}}},"name": "default"}), headers: {'Content-Type': 'application/json'} }));
                                                    
                                                    Promise.all(searchIndexCreation).then((searchIndexCreated) => {
                                                        res.status(200).send('Ok');
                                                    }).catch(error => {
                                                        insertErrorLog({db:req.headers.site},error);
                                                        res.status(500);
                                                        res.render('error', { error: error });
                                                    });
                                                }).catch(error => {
                                                    insertErrorLog({db:req.headers.site},error);
                                                    res.status(500);
                                                    res.render('error', { error: error });
                                                });
                                            }).catch(err => {
                                                insertErrorLog({db:req.headers.site},err);
                                                res.status(500);
                                                res.render('error', { error: err });
                                            })
                                        }
                                    });
                                }
                            });
                        }).catch(err => {
                            insertErrorLog({db:req.headers.site},err);
                            res.status(500);
                            res.render('error', { error: err });
                        }); 
                    }).catch(err => {
                        insertErrorLog({db:req.headers.site},err);
                        res.status(500);
                        res.render('error', { error: err });
                    });                        
                }).catch(err => {
                    insertErrorLog({db:req.headers.site},err);
                    res.status(500);
                    res.render('error', { error: err });
                });
            }).catch(error => {
                insertErrorLog({db:req.headers.site},error);
                res.status(500);
                res.render('error', { error: error });
            });
        } else {
            insertErrorLog({db:req.headers.site}, new Error("Missing db or label parameter") );
            res.status(400);
            res.render('error', { error: new Error("Missing db or label parameter") });
        }
    }).catch(err => {
        insertErrorLog({db:req.headers.site},error);
        res.status(403);
        res.render('error', { error: err});
    });
});

router.delete('/sites', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        const { _id } = req.query;
        if(_id && _id.trim().length > 0 ) {
            client.connect().then(value => {
                client.db(DEFAULT_APPLICATION_DB).collection("sites").deleteOne({ _id: new ObjectID(_id)})
                .then(result => {
                    res.status(200).send('Ok');
                }).catch(error => {
                    insertErrorLog({db:DEFAULT_APPLICATION_DB},error);
                    res.status(500);
                    res.render('error', { error: error });
                });
            }).catch(error => {
                insertErrorLog({db:DEFAULT_APPLICATION_DB},error);
                res.status(500);
                res.render('error', { error: error });
            });
        } else {
            insertErrorLog({db:DEFAULT_APPLICATION_DB}, new Error("Missing id parameter"));
            res.status(400);
            res.render('error', { error: new Error("Missing id parameter") });
        }
    }).catch(err => {
        insertErrorLog({db:DEFAULT_APPLICATION_DB},err);
        res.status(403);
        res.render('error', { error: err });
    });
});

const getModuleSettingsForSite = (siteDetails, forModule) => {
    return new Promise((resolve, reject) => {
        const client1 = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        client1.connect().then(value => {
                var promises = [];
                promises.push(client1.db(DEFAULT_APPLICATION_DB).collection("orgSettings").findOne({module:forModule}));
                promises.push(client1.db(siteDetails.db).collection("siteSettings").findOne({module:forModule}));
                
                Promise.all(promises).then((values) => {
                    resolve([{...values[0], level:"org"}, {...values[1], level:"site"}]);
                }).catch(err => {
                    reject(err);
               });
       }) .catch(error => {
        reject(err);
       });
    });
}
router.get('/settings', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            if (req.query.module && req.query.module.trim().length > 0) {
                getModuleSettingsForSite(siteDetails, req.query.module).then(mergedSettings => {
                    res.json(mergedSettings);
                }).catch(err => {
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                })
            } else {
                insertErrorLog(siteDetails, new Error("Missing module parameter"));
                res.status(400);
                res.render('error', { error: new Error("Missing module parameter") });
            }
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    });
});

router.post('/settings/licence', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            if(req.body.licence){
                readLicence(req.body.licence).then(data => {
                    var txtDecoder = new TextDecoder();
                    const dataMsg = nacl.util.decodeBase64(data);
                    const publicKey = nacl.util.decodeBase64(config.licence.pubKey);
                    const licenceJson = nacl.sign.open(dataMsg, publicKey);
                    var licenceObj = JSON.parse(txtDecoder.decode(licenceJson));
                    if(licenceObj && licenceObj.db === siteDetails.db) 
                        res.json(licenceObj);
                    else {
                        insertErrorLog(siteDetails,{message:"Invalid licence for site", code:'ERR_INVALID_LICENCE'});
                        res.status(400);
                        res.render('error', { error: {message:"Invalid licence for site", code:'ERR_INVALID_LICENCE'}});
                    }   
                }).catch(err => {
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                })
            } else {
                insertErrorLog(siteDetails, new Error("Missing licence parameter") );
                res.status(400);
                res.render('error', { error: new Error("Missing licence parameter") });
            }
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
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

router.post('/settings', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            if (req.body.module && req.body.module.trim().length > 0 && req.body.level && req.body.level.trim().length > 0) {
                const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

                const { settings } = req.body;

                var targetDB = "projetkhiron";
                var targetColl = "orgSettings";
                if(req.body.level === "site") {
                    targetDB = siteDetails.db;
                    targetColl = "siteSettings";
                }

                let query = { module:req.body.module};

                client.connect().then(connected => {
                    client.db(targetDB).collection(targetColl).updateOne(query, { $set: { settings: settings } }, { upsert: false }).then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
                }).catch(error => {
                    insertErrorLog(siteDetails,error);
                    res.status(500);
                    res.render('error', { error: error });
                })
            } else {
                insertErrorLog(siteDetails, new Error("Missing module or level parameter"));
                res.status(400);
                res.render('error', { error: new Error("Missing module or level parameter")});
            }
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err});
    })
});

router.get('/bearer/analysis', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            var MS_PER_MINUTE = 60000;

            if (req.query.type === "outOfService") {
                var beforeDate = new Date(new Date().getTime() - (parseInt(req.query.seviceLevel) * MS_PER_MINUTE));

                query = { requestedOn: { $lte: beforeDate }, completedOn: { $eq: new Date(0) } }
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("bearerRequests").find(query).sort({ requestedOn: 1 }).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/cleaner/analysis', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            let query = {};
            var MS_PER_MINUTE = 60000;

            if (req.query.type === "outOfService") {
                var beforeDate = new Date(new Date().getTime() - (parseInt(req.query.seviceLevel) * MS_PER_MINUTE));

                query = { requestedOn: { $lte: beforeDate }, completedOn: { $eq: new Date(0) } }
            }

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("cleanerRequests").find(query).sort({ requestedOn: 1 }).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

router.get('/visitor/requests', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
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

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("visitorRequests").find(query).sort({ requestedOn: -1 }).toArray(function (err2, result) {
                    if (err2) {
                        insertErrorLog(siteDetails,err2);
                        res.status(500);
                        res.render('error', { error: err2 });
                    } else {
                        res.json(result);
                    }
                    client.close();
                });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err});
    })
});

router.put('/visitor/requests', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                const { requestFor, requestedOn, options } = req.body;
                client.db(siteDetails.db).collection("visitorRequests").insertOne({ _id: new ObjectID(), requestFor: requestFor, requestedOn: new Date(requestedOn), options: options })
                    .then(result => {
                        res.status(200).send('Ok');
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(403);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err});
    })
});

router.get('/visitor/external', function (req, res, next) {
    getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
        if(req.headers.apikey && req.headers.apikey.trim().length > 0) {
            getModuleSettingsForSite(siteDetails, "visitor").then(settings => {
                var mergedSettings = {}
                if(settings[0].settings.request &&settings[1].settings.request) {
                    mergedSettings = { settings:{ ...settings[0].settings, ...settings[1].settings,  request:{properties:[...settings[0].settings.request.properties, ...settings[1].settings.request.properties]}}}
                } else {
                    mergedSettings = { settings:{ ...settings[0].settings, ...settings[1].settings } }
                }
                if(req.headers.apikey === mergedSettings.settings.apikey){
                    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
                    client.connect().then(connected =>{
                        client.db(siteDetails.db).collection("floors").find({}).sort({ label: 1 }).toArray().then(results => {
                            res.json({site:siteDetails, config:mergedSettings, floors:results});
                        }).catch(err => {
                            insertErrorLog(siteDetails,err);
                            res.status(500);
                            res.render('error', { error: err});
                        }).finally(() => {
                            client.close();
                        });
                    }).catch(err => {
                        insertErrorLog(siteDetails,err);
                        res.status(500);
                        res.render('error', { error: err});
                    });
                } else {
                    insertErrorLog(siteDetails,new Error("Not authorized"));
                    res.status(403);
                    res.render('error', { error: new Error("Not authorized")});
                }
            }).catch(err => {
                insertErrorLog(siteDetails,err);
                res.status(500);
                res.render('error', { error: err });
            });
        } else {
            insertErrorLog(siteDetails,new Error("Not authorized"));
            res.status(403);
            res.render('error', { error: new Error("Not authorized")});
        }
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(400);
        res.render('error', { error: err});
    });
});

router.get('/visitor/external/floor/:id', function (req, res, next) {
    getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
        if(req.headers.apikey && req.headers.apikey.trim().length > 0) {
            getModuleSettingsForSite(siteDetails, "visitor").then(settings => {
                var mergedSettings = {}
                if(settings[0].settings.request &&settings[1].settings.request) {
                    mergedSettings = { settings:{ ...settings[0].settings, ...settings[1].settings,  request:{properties:[...settings[0].settings.request.properties, ...settings[1].settings.request.properties]}}}
                } else {
                    mergedSettings = { settings:{ ...settings[0].settings, ...settings[1].settings } }
                }
                if(req.headers.apikey === mergedSettings.settings.apikey){
                    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
                    client.connect().then(connected =>{
                        var o_id = new mongo.ObjectID(req.params.id);
                        client.db(siteDetails.db).collection("floors").findOne({ _id: o_id })
                            .then(result => {
                                if (result)
                                    res.json(result);
                                else
                                    res.json([]);
                            })
                            .catch(error => {
                                insertErrorLog(siteDetails,error);
                                res.status(500);
                                res.render('error', { error: error });
                            })
                            .finally(() => {
                                client.close();
                            });
                    }).catch(err => {
                        insertErrorLog(siteDetails,err);
                        res.status(500);
                        res.render('error', { error: err});
                    });
                } else {
                    insertErrorLog(siteDetails,new Error("Not authorized"));
                    res.status(403);
                    res.render('error', { error: new Error("Not authorized")});
                }
            }).catch(err => {
                insertErrorLog(siteDetails,err);
                res.status(500);
                res.render('error', { error: err });
            });
        } else {
            insertErrorLog(siteDetails,new Error("Not authorized"));
            res.status(403);
            res.render('error', { error: new Error("Not authorized")});
        }
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(400);
        res.render('error', { error: err});
    });
});

router.put('/visitor/external', function (req, res, next) {
    getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
        if(req.headers.apikey && req.headers.apikey.trim().length > 0) {
            getModuleSettingsForSite(siteDetails, "visitor").then(settings => {
                var mergedSettings = {}
                if(settings[0].settings.request &&settings[1].settings.request) {
                    mergedSettings = { settings:{ ...settings[0].settings, ...settings[1].settings,  request:{properties:[...settings[0].settings.request.properties, ...settings[1].settings.request.properties]}}}
                } else {
                    mergedSettings = { settings:{ ...settings[0].settings, ...settings[1].settings } }
                }
                if(req.headers.apikey === mergedSettings.settings.apikey){
                    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
                    client.connect().then(connected =>{
                        const { requestFor, requestedOn, options } = req.body;
                        client.db(siteDetails.db).collection("visitorRequests").insertOne({ _id: new ObjectID(), requestFor: requestFor, requestedOn: new Date(requestedOn), options: options })
                            .then(result => {
                                res.status(200).send('Ok');
                            })
                            .catch(error => {
                                insertErrorLog(siteDetails,error);
                                res.status(500);
                                res.render('error', { error: error });
                            })
                            .finally(() => {
                                client.close();
                            });
                    }).catch(err => {
                        insertErrorLog(siteDetails,err);
                        res.status(500);
                        res.render('error', { error: err});
                    });
                } else {
                    insertErrorLog(siteDetails,new Error("Not authorized"));
                    res.status(403);
                    res.render('error', { error: new Error("Not authorized")});
                }
            }).catch(err => {
                insertErrorLog(siteDetails,err);
                res.status(500);
                res.render('error', { error: err });
            });
        } else {
            insertErrorLog(siteDetails,new Error("Not authorized"));
            res.status(403);
            res.render('error', { error: new Error("Not authorized")});
        }
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(400);
        res.render('error', { error: err});
    });
});

router.get('/visitor/requests/stats', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

            client.connect(err => {
                if (err) {
                    client.close();
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                    return;
                }

                client.db(siteDetails.db).collection("visitorRequestsStats").findOne({ type: req.query.type })
                    .then(result => {
                        if (result)
                            res.json(result.data);
                        else
                            res.json([]);
                    })
                    .catch(error => {
                        insertErrorLog(siteDetails,error);
                        res.status(500);
                        res.render('error', { error: error });
                    })
                    .finally(() => {
                        client.close();
                    });
            });
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err});
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
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

const performSearch = (site, floorID, sectionID, bedID, visitorOptions, bearerOptions, cleanerOptions, fromDate, toDate, searchVisitor, searchBearer, searchCleaner, multiSiteSearch) => {
    return new Promise((resolve, reject) => {
        const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        client.connect().then(value => {
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
    
                if(!multiSiteSearch) {
                    if (bedID) {
                        visitorPipelineStages.push({ $match: { "requestFor.type": "bed", "requestFor._id": bedID } });
                    } else if (sectionID) {
                        visitorPipelineStages.push({ $match: { "requestFor.section._id": sectionID } });
                    } else if (floorID) {
                        visitorPipelineStages.push({ $match: { "requestFor.section.floorID": floorID } });
                    }
                }
    
                visitorPipelineStages.push({ $match: { requestedOn: { $lte: new Date(toDate), $gte: new Date(fromDate) } } });
    
                promises.push(client.db(site.db).collection("visitorRequests").aggregate(visitorPipelineStages).toArray());
    
                currentPromiseIdx = currentPromiseIdx + 1;
                visitorPromiseIdx = currentPromiseIdx;
            }
    
            if (searchBearer) {
                let bearerPipelineStages = [];
                if (bearerOptions) {
                    //first stage of pipeline has to be $search if there is any
                    bearerPipelineStages = generateInitialSearchPipeline(bearerOptions);
                }
    
                if(!multiSiteSearch) {
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
                }

                bearerPipelineStages.push({ $match: { completedOn: { $lte: new Date(toDate), $gte: new Date(fromDate) } } });
    
                promises.push(client.db(site.db).collection("bearerRequests").aggregate(bearerPipelineStages).toArray());
    
                currentPromiseIdx = currentPromiseIdx + 1;
                bearerPromiseIdx = currentPromiseIdx;
            }
    
            if (searchCleaner) {
                let cleanerPipelineStages = [];
                if (cleanerOptions) {
                    //first stage of pipeline has to be $search if there is any
                    cleanerPipelineStages = generateInitialSearchPipeline(cleanerOptions);
                }
    
                if(!multiSiteSearch) {
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
                }

                cleanerPipelineStages.push({ $match: { completedOn: { $lte: new Date(toDate), $gte: new Date(fromDate) } } });
    
                promises.push(client.db(site.db).collection("cleanerRequests").aggregate(cleanerPipelineStages).toArray());
    
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
                resolve({site:site, results:sortedEvents});
            }).catch(err => {
                reject(err);
            }).finally(() => {
                client.close();
            })
        }).catch(err => {
            reject(err);
        });
    });
}

router.post('/requests/search', function (req, res, next) {
    userAccessAuthorized(req).then(isAuthorized => {
        getSiteDetailsSiteID(req.headers.site).then(siteDetails => {
            const { floorID, sectionID, bedID, visitorOptions, bearerOptions, cleanerOptions, fromDate, toDate, searchVisitor, searchBearer, searchCleaner, multiSiteSearch, sites } = req.body;
            if(multiSiteSearch) {
                var queries = [];
                sites.forEach(site => {
                    queries.push(performSearch(site, floorID, sectionID, bedID, visitorOptions, bearerOptions, cleanerOptions, fromDate, toDate, searchVisitor, searchBearer, searchCleaner));
                });
                Promise.all(queries).then((values) => {
                    res.json(values);
                }).catch(err => {
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                });
            } else {
                performSearch(siteDetails, floorID, sectionID, bedID, visitorOptions, bearerOptions, cleanerOptions, fromDate, toDate, searchVisitor, searchBearer, searchCleaner).then(result => {
                    res.json([result]);
                }).catch(err => {
                    insertErrorLog(siteDetails,err);
                    res.status(500);
                    res.render('error', { error: err });
                });
            }
        }).catch(err => {
            insertErrorLog({db:req.headers.site},err);
            res.status(400);
            res.render('error', { error: err });
        });
    }).catch(err => {
        insertErrorLog({db:req.headers.site},err);
        res.status(403);
        res.render('error', { error: err });
    })
});

module.exports = router;
