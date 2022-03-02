"use strict";
require("dotenv").config();

const DbService = require("../mixins/db.mixin");
const cacheCleanerMixin = require("../mixins/cache.cleaner.mixin");

const { MoleculerClientError } = require("moleculer").Errors;
const Error = require("moleculer-web").Errors;
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const mkdir = require("mkdirp").sync;
const mime = require("mime-types");

const uploadDir = path.join(__dirname, "__uploads");
mkdir(uploadDir);

module.exports = {
	name: "users",
	mixins: [DbService("users"), cacheCleanerMixin(["cache.clean.users"])],
	settings: {
		rest: "/users",
		JWT_SECRET: process.env.JWT_SECRET || "jwt-health",
		fields: [
			"_id",
			"phoneNumber",
			"password",
			"fullname",
			"birthday",
			"gender",
			"inviteCode",
			"city",
			"address",
		],

		entityValidator: {
			phoneNumber: {
				type: "string",
				pattern: /(84|0[3|5|7|8|9])+([0-9]{8})\b/,
			},
			password: { type: "string", min: 6 },
			fullname: { type: "string", min: 1 },
			birthday: { type: "string" },
			gender: { type: "boolean" },
			inviteCode: { type: "string", optional: true },
			city: { type: "string" },
			address: { type: "string", optional: true },
			image: { type: "string", optional: true },
		},
		routes: [
			{
				authorization: true,
			},
		],
	},
	actions: {
		create: {
			rest: "POST /",
			params: {
				phoneNumber: {
					type: "string",
					pattern: /(84|0[3|5|7|8|9])+([0-9]{8})\b/,
				},
				password: { type: "string" },
				fullname: { type: "string" },
				birthday: { type: "string" },
				gender: { type: "boolean" },
				inviteCode: { type: "string", optional: true },
				city: { type: "string" },
				address: { type: "string", optional: true },
				image: { type: "string", optional: true },
			},
			async handler(ctx) {
				let entity = ctx.params;
				await this.validateEntity(entity);
				if (entity.phoneNumber) {
					const found = await this.adapter.findOne({
						phoneNumber: entity.phoneNumber,
					});

					if (found) {
						throw new MoleculerClientError(
							"Số điện thoại đã tồn tại!",
							422,
							"",
							[{ field: "phoneNumber", message: "đã tồn tại!" }]
						);
					}
				}

				entity.password = bcryptjs.hashSync(entity.password, 10);
				entity.image = entity.image || null;

				const doc = await this.adapter.insert(entity);

				const user = await this.transformEntity(
					doc,
					true,
					ctx.meta.token
				);
				await this.entityChanged("created", user, ctx);
				return user;
			},
		},
		login: {
			rest: "POST /login",
			params: {
				phoneNumber: { type: "string" },
				password: { type: "string", min: 6 },
			},
			async handler(ctx) {
				const { phoneNumber, password } = ctx.params;

				const user = await this.adapter.findOne({ phoneNumber });
				if (!user)
					throw new MoleculerClientError(
						"Tài khoản không tồn tại!",
						422,
						"",
						[{ field: "phoneNumber", message: "is not found" }]
					);

				const res = await bcryptjs.compare(password, user.password);
				if (!res) {
					throw new MoleculerClientError(
						"Tài khoản hoặc tên đăng nhập không đÚng!",
						422,
						"",
						[{ field: "password", message: "is not correct" }]
					);
				}

				const doc = await this.transformDocuments(ctx, {}, user);
				return await this.transformEntity(doc, true, ctx.meta.token);
			},
		},

		resolveToken: {
			cache: {
				keys: ["token"],
				ttl: 60 * 60, // 1 hour
			},
			params: {
				token: "string",
			},
			async handler(ctx) {
				const decoded = await new this.Promise((resolve, reject) => {
					jwt.verify(
						ctx.params.token,
						this.settings.JWT_SECRET,
						(err, decoded) => {
							if (err) return reject(err);

							resolve(decoded);
						}
					);
				});

				if (decoded.id) return this.getById(decoded.id);
			},
		},

		me: {
			auth: "required",
			rest: "GET /me",
			cache: {
				keys: ["#userID"],
			},
			async handler(ctx) {
				const user = await this.getById(ctx.meta.user._id);
				if (!user)
					throw new MoleculerClientError("User not found!", 404);
				const doc = await this.transformDocuments(ctx, {}, user);
				return await this.transformEntity(doc, true, ctx.meta.token);
			},
		},

		update: {
			auth: "required",
			rest: "PUT /",
			params: {
				password: { type: "string", optional: true },
				fullname: { type: "string", optional: true },
				birthday: { type: "string", optional: true },
				gender: { type: "boolean", optional: true },
				inviteCode: { type: "string", optional: true },
				city: { type: "string", optional: true },
				address: { type: "string", optional: true },
				image: { type: "string", optional: true },
			},
			async handler(ctx) {
				const entity = ctx.params;
				const update = {
					$set: entity,
				};
				const doc = await this.adapter.updateById(
					ctx.meta.user._id,
					update
				);

				const user = await this.transformDocuments(ctx, {}, doc);
				const json = await this.transformEntity(
					user,
					true,
					ctx.meta.token
				);
				await this.entityChanged("updated", json, ctx);
				return json;
			},
		},

		delete: {
			auth: "required",
			rest: "DELETE /:id",
			async handler(ctx) {
				const id = ctx.params;
				const user = await this.getById(id);
				if (!user)
					throw new MoleculerClientError("User not found!", 404);
				const res = await this.adapter.removeById(id);
				await this.entityChanged("removed", res, ctx);
				return res;
			},
		},

		uploadImage: {
			auth: "required",
			rest: "PUT /avatar",
			async handler(ctx) {
				this.logger.info("Received upload $params:", ctx.meta.$params);
				const filePath = path.join(
					uploadDir,
					ctx.meta.filename || this.randomName()
				);
				const f = fs.createWriteStream(filePath);
				f.on("close", async () => {
					this.logger.info(`Uploaded file stored in '${filePath}'`);
					const update = {
						$set: {
							image: filePath,
						},
					};
					const doc = await this.adapter.updateById(
						ctx.meta.user._id,
						update
					);

					const user = await this.transformDocuments(ctx, {}, doc);
					const json = await this.transformEntity(
						user,
						true,
						ctx.meta.token
					);
					await this.entityChanged("updated", json, ctx);
				});

				ctx.params.on("error", (err) => {
					this.logger.info("File error received", err.message);

					f.destroy(err);
				});

				f.on("error", () => {
					fs.unlinkSync(filePath);
				});

				return ctx.params.pipe(f);
			},
		},

		getImage: {
			auth: "required",
			rest: "GET /avatar",
			async handler(ctx) {
				const user = await this.getById(ctx.meta.user._id);
				if (!user)
					throw new MoleculerClientError("User not found!", 404);

				ctx.meta.$responseType = "image/png";
				return fs.createReadStream(user.image);
			},
		},

		get: false,
		list: false,
		remove: false,
	},
	methods: {
		generateJWT(user) {
			const today = new Date();
			const exp = new Date(today);
			exp.setDate(today.getDate() + 60);

			return jwt.sign(
				{
					id: user._id,
					phoneNumber: user.phoneNumber,
					exp: Math.floor(exp.getTime() / 1000),
				},
				this.settings.JWT_SECRET
			);
		},
		transformEntity(user, withToken, token) {
			if (user) {
				if (withToken) {
					user.token = token || this.generateJWT(user);
				}
			}
			return user;
		},
		randomName() {
			return "unnamed_" + Date.now() + ".png";
		},
		getImage(imagePath) {
			const filePath = path.join(imagePath);
			if (!fs.existsSync(filePath)) return new NotFoundError();
			return fs.createReadStream(filePath);
		},
	},
};
