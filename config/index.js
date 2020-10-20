module.exports = {
	server: {
		port: process.env.SERVER_PORT
	},
	database: {
		connectionstring: process.env.DATABASE_CONNECTIONSTRING
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