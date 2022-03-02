"use strict";

const _ = require("lodash");
const ApiGateway = require("moleculer-web");
const { UnAuthorizedError } = ApiGateway.Errors;

module.exports = {
	name: "api",
	mixins: [ApiGateway],

	settings: {
		port: process.env.PORT || 3000,

		routes: [
			{
				path: "/api",

				authorization: true,
				autoAliases: true,

				cors: true,

				bodyParsers: {
					json: {
						strict: false,
					},
					urlencoded: {
						extended: false,
					},
				},
				aliases: {
					"PUT /users/avatar": {
						type: "multipart",
						busboyConfig: {
							limits: {
								files: 1,
							},
						},
						action: "users.uploadImage",
					},
				},

				busboyConfig: {
					limits: {
						files: 1,
					},
				},
			},
		],

		assets: {
			folder: "./public",
		},

		onError(req, res, err) {
			res.setHeader("Content-type", "application/json; charset=utf-8");
			res.writeHead(err.code || 500);

			if (err.code == 422) {
				let o = {};
				err.data.forEach((e) => {
					let field = e.field.split(".").pop();
					o[field] = e.message;
				});

				res.end(JSON.stringify({ errors: o }, null, 2));
			} else {
				const errObj = _.pick(err, [
					"name",
					"message",
					"code",
					"type",
					"data",
				]);
				res.end(JSON.stringify(errObj, null, 2));
			}
			this.logResponse(req, res, err ? err.ctx : null);
		},
	},

	methods: {
		async authorize(ctx, route, req) {
			let token;
			if (req.headers.authorization) {
				let type = req.headers.authorization.split(" ")[0];
				if (type === "Token" || type === "Bearer")
					token = req.headers.authorization.split(" ")[1];
			}

			let user;
			if (token) {
				try {
					user = await ctx.call("users.resolveToken", { token });
					if (user) {
						this.logger.info(
							"Authenticated via JWT: ",
							user.phoneNumber
						);

						ctx.meta.user = _.pick(user, [
							"_id",
							"phoneNumber",
							"password",
							"fullname",
							"birthday",
							"gender",
							"inviteCode",
							"city",
							"address",
						]);

						ctx.meta.token = token;
						ctx.meta.userID = user._id;
					}
				} catch (err) {}
			}

			if (req.$action.auth == "required" && !user)
				throw new UnAuthorizedError();
		},
	},
};
