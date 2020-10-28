module.exports = {
	server: {
		port: process.env.SERVER_PORT
	},
	database: {
		connectionstring: process.env.DATABASE_CONNECTIONSTRING,
		groupid: process.env.DATABASE_GROUPID,
		publicKey:process.env.DATABASE_PUBLIC_KEY,
		privateKey:process.env.DATABASE_PRIVATE_KEY,
		cluster:process.env.DATABASE_CLUSTER,
	},
	host:{
		cors: process.env.CORS_ORIGIN
	},
	aws:{
		accessKeyId: process.env.AWS_KEY_ID,
		secretAccessKey:  process.env.AWS_SECRET,
		region: process.env.AWS_REGION,
	},
	cognito: {
		region: process.env.COGNITO_REGION,
		userPoolID: process.env.COGNITO_USER_POOLS_ID,
		userPoolsWebClientID: process.env.COGNITO_WEB_CLIENT_ID
	},
	licence:{
		pubKey: process.env.LICENCE_PUB_KEY,
	}
}