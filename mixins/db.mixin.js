"use strict";
const DbService = require("moleculer-db");

module.exports = function (collection) {
	const MONGO_URI = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.pa3x2.mongodb.net/social?retryWrites=true&w=majority`;
	const MongoAdapter = require("moleculer-db-adapter-mongo");

	return {
		mixins: [DbService],
		adapter: new MongoAdapter(MONGO_URI, {
			useNewUrlParser: true,
			useUnifiedTopology: true,
		}),
		collection,
	};
};
