/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */,
/* 1 */
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),
/* 2 */
/***/ ((module) => {

module.exports = require("path");

/***/ }),
/* 3 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.restaurantModule = void 0;
const tslib_1 = __webpack_require__(4);
const common_1 = __webpack_require__(5);
const config_1 = __webpack_require__(6);
const graphql_1 = __webpack_require__(7);
const apollo_1 = __webpack_require__(8);
const jwt_1 = __webpack_require__(9);
const prisma_service_1 = __webpack_require__(10);
const email_module_1 = __webpack_require__(12);
const restaurant_service_1 = __webpack_require__(16);
const restaurant_resolver_1 = __webpack_require__(19);
let restaurantModule = class restaurantModule {
};
exports.restaurantModule = restaurantModule;
exports.restaurantModule = restaurantModule = tslib_1.__decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                isGlobal: true,
            }),
            graphql_1.GraphQLModule.forRoot({
                driver: apollo_1.ApolloFederationDriver,
                autoSchemaFile: {
                    federation: 2,
                },
            }),
            email_module_1.EmailModule,
        ],
        controllers: [],
        providers: [
            restaurant_service_1.RestaurantService,
            config_1.ConfigService,
            jwt_1.JwtService,
            prisma_service_1.PrismaService,
            restaurant_resolver_1.RestaurantResolver,
        ],
    })
], restaurantModule);


/***/ }),
/* 4 */
/***/ ((module) => {

module.exports = require("tslib");

/***/ }),
/* 5 */
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),
/* 6 */
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),
/* 7 */
/***/ ((module) => {

module.exports = require("@nestjs/graphql");

/***/ }),
/* 8 */
/***/ ((module) => {

module.exports = require("@nestjs/apollo");

/***/ }),
/* 9 */
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),
/* 10 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PrismaService = void 0;
const tslib_1 = __webpack_require__(4);
const common_1 = __webpack_require__(5);
const client_1 = __webpack_require__(11);
let PrismaService = class PrismaService extends client_1.PrismaClient {
    async onModuleInit() {
        await this.$connect();
    }
};
exports.PrismaService = PrismaService;
exports.PrismaService = PrismaService = tslib_1.__decorate([
    (0, common_1.Injectable)()
], PrismaService);


/***/ }),
/* 11 */
/***/ ((module) => {

module.exports = require("@prisma/client");

/***/ }),
/* 12 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmailModule = void 0;
const tslib_1 = __webpack_require__(4);
const common_1 = __webpack_require__(5);
const email_service_1 = __webpack_require__(13);
const mailer_1 = __webpack_require__(14);
const config_1 = __webpack_require__(6);
const path_1 = __webpack_require__(2);
const ejs_adapter_1 = __webpack_require__(15);
let EmailModule = class EmailModule {
};
exports.EmailModule = EmailModule;
exports.EmailModule = EmailModule = tslib_1.__decorate([
    (0, common_1.Global)(),
    (0, common_1.Module)({
        imports: [
            mailer_1.MailerModule.forRootAsync({
                useFactory: async (config) => ({
                    transport: {
                        host: config.get('SMTP_HOST'),
                        secure: true,
                        auth: {
                            user: config.get('SMTP_MAIL'),
                            pass: config.get('SMTP_PASSWORD'),
                        },
                    },
                    defaults: {
                        from: 'Becodemy',
                    },
                    template: {
                        dir: (0, path_1.join)(__dirname, '../../../apps/api-restuarants/email-templates'),
                        adapter: new ejs_adapter_1.EjsAdapter(),
                        options: {
                            strict: false,
                        },
                    },
                }),
                inject: [config_1.ConfigService],
            }),
        ],
        providers: [email_service_1.EmailService],
        exports: [email_service_1.EmailService],
    })
], EmailModule);


/***/ }),
/* 13 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EmailService = void 0;
const tslib_1 = __webpack_require__(4);
const mailer_1 = __webpack_require__(14);
const common_1 = __webpack_require__(5);
let EmailService = class EmailService {
    constructor(mailService) {
        this.mailService = mailService;
    }
    async sendMail({ subject, email, name, activation_token, template, }) {
        await this.mailService.sendMail({
            to: email,
            subject,
            template,
            context: {
                name,
                activation_token,
            },
        });
    }
};
exports.EmailService = EmailService;
exports.EmailService = EmailService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof mailer_1.MailerService !== "undefined" && mailer_1.MailerService) === "function" ? _a : Object])
], EmailService);


/***/ }),
/* 14 */
/***/ ((module) => {

module.exports = require("@nestjs-modules/mailer");

/***/ }),
/* 15 */
/***/ ((module) => {

module.exports = require("@nestjs-modules/mailer/dist/adapters/ejs.adapter");

/***/ }),
/* 16 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RestaurantService = void 0;
const tslib_1 = __webpack_require__(4);
const common_1 = __webpack_require__(5);
const jwt_1 = __webpack_require__(9);
const prisma_service_1 = __webpack_require__(10);
const config_1 = __webpack_require__(6);
const email_service_1 = __webpack_require__(13);
const bcrypt = tslib_1.__importStar(__webpack_require__(17));
const send_token_1 = __webpack_require__(18);
let RestaurantService = class RestaurantService {
    constructor(jwtService, prisma, configService, emailService) {
        this.jwtService = jwtService;
        this.prisma = prisma;
        this.configService = configService;
        this.emailService = emailService;
    }
    // register restaurant service
    async registerRestaurant(registerDto, response) {
        const { name, country, city, address, email, phone_number, password } = registerDto;
        const isEmailExist = await this.prisma.restaurant.findUnique({
            where: {
                email,
            },
        });
        if (isEmailExist) {
            throw new common_1.BadRequestException('Restaurant already exist with this email!');
        }
        const usersWithPhoneNumber = await this.prisma.restaurant.findUnique({
            where: {
                phone_number,
            },
        });
        if (usersWithPhoneNumber) {
            throw new common_1.BadRequestException('Restaurant already exist with this phone number!');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const restaurant = {
            name,
            country,
            city,
            address,
            email,
            phone_number,
            password: hashedPassword,
        };
        const activationToken = await this.createActivationToken(restaurant);
        const client_side_uri = this.configService.get('CLIENT_SIDE_URI');
        const activation_token = `${client_side_uri}/activate-account/${activationToken}`;
        await this.emailService.sendMail({
            email,
            subject: 'Activate your restaurant account!',
            template: './activation-mail',
            name,
            activation_token,
        });
        return {
            message: 'Please check your email to activate your account',
            response,
        };
    }
    // create activation token
    async createActivationToken(restaurant) {
        const activationToken = this.jwtService.sign({
            restaurant,
        }, {
            secret: this.configService.get('JWT_SECRET_KEY'),
            expiresIn: '5m',
        });
        return activationToken;
    }
    // activation restaurant
    async activateRestaurant(activationDto, response) {
        const { activationToken } = activationDto;
        const newRestaurant = this.jwtService.verify(activationToken, {
            secret: this.configService.get('JWT_SECRET_KEY'),
        });
        if (newRestaurant?.exp * 1000 < Date.now()) {
            throw new common_1.BadRequestException('Invalid activation code');
        }
        const { name, country, city, phone_number, password, email, address } = newRestaurant.restaurant;
        const existRestaurant = await this.prisma.restaurant.findUnique({
            where: {
                email,
            },
        });
        if (existRestaurant) {
            throw new common_1.BadRequestException('Restaurant already exist with this email!');
        }
        const restaurant = await this.prisma.restaurant.create({
            data: {
                name,
                email,
                address,
                country,
                city,
                phone_number,
                password,
            },
        });
        return { restaurant, response };
    }
    // Login restaurant
    async LoginRestuarant(loginDto) {
        const { email, password } = loginDto;
        const restaurant = await this.prisma.restaurant.findUnique({
            where: {
                email,
            },
        });
        if (restaurant &&
            (await this.comparePassword(password, restaurant.password))) {
            const tokenSender = new send_token_1.TokenSender(this.configService, this.jwtService);
            return tokenSender.sendToken(restaurant);
        }
        else {
            return {
                user: null,
                accessToken: null,
                refreshToken: null,
                error: {
                    message: 'Invalid email or password',
                },
            };
        }
    }
    // compare with hashed password
    async comparePassword(password, hashedPassword) {
        return await bcrypt.compare(password, hashedPassword);
    }
    // get logged in restaurant
    async getLoggedInRestaurant(req) {
        const restaurant = req.restaurant;
        const refreshToken = req.refreshtoken;
        const accessToken = req.accesstoken;
        return { restaurant, accessToken, refreshToken };
    }
    // log out restaurant
    async Logout(req) {
        req.restaurant = null;
        req.refreshtoken = null;
        req.accesstoken = null;
        return { message: 'Logged out successfully!' };
    }
};
exports.RestaurantService = RestaurantService;
exports.RestaurantService = RestaurantService = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _a : Object, typeof (_b = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _b : Object, typeof (_c = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _c : Object, typeof (_d = typeof email_service_1.EmailService !== "undefined" && email_service_1.EmailService) === "function" ? _d : Object])
], RestaurantService);


/***/ }),
/* 17 */
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),
/* 18 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TokenSender = void 0;
class TokenSender {
    constructor(config, jwt) {
        this.config = config;
        this.jwt = jwt;
    }
    sendToken(restaurant) {
        const accessToken = this.jwt.sign({
            id: restaurant.id,
        }, {
            secret: this.config.get('ACCESS_TOKEN_SECRET'),
            expiresIn: '1m',
        });
        const refreshToken = this.jwt.sign({
            id: restaurant.id,
        }, {
            secret: this.config.get('REFRESH_TOKEN_SECRET'),
            expiresIn: '3d',
        });
        return { restaurant, accessToken, refreshToken };
    }
}
exports.TokenSender = TokenSender;


/***/ }),
/* 19 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b, _c, _d, _e, _f, _g;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RestaurantResolver = void 0;
const tslib_1 = __webpack_require__(4);
const graphql_1 = __webpack_require__(7);
const restaurant_service_1 = __webpack_require__(16);
const user_type_1 = __webpack_require__(20);
const restaurant_dto_1 = __webpack_require__(22);
const common_1 = __webpack_require__(5);
const auth_guard_1 = __webpack_require__(24);
let RestaurantResolver = class RestaurantResolver {
    constructor(restaurantService) {
        this.restaurantService = restaurantService;
    }
    async registerRestaurant(registerDto, context) {
        const { message } = await this.restaurantService.registerRestaurant(registerDto, context.res);
        return { message };
    }
    async activateRestaurant(activationDto, context) {
        return await this.restaurantService.activateRestaurant(activationDto, context.res);
    }
    async LoginRestaurant(email, password) {
        return await this.restaurantService.LoginRestuarant({ email, password });
    }
    async getLoggedInRestaurant(context) {
        return await this.restaurantService.getLoggedInRestaurant(context.req);
    }
    async logOutRestaurant(context) {
        return await this.restaurantService.Logout(context.req);
    }
};
exports.RestaurantResolver = RestaurantResolver;
tslib_1.__decorate([
    (0, graphql_1.Mutation)(() => user_type_1.RegisterResponse),
    tslib_1.__param(0, (0, graphql_1.Args)('registerDto')),
    tslib_1.__param(1, (0, graphql_1.Context)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_b = typeof restaurant_dto_1.RegisterDto !== "undefined" && restaurant_dto_1.RegisterDto) === "function" ? _b : Object, Object]),
    tslib_1.__metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], RestaurantResolver.prototype, "registerRestaurant", null);
tslib_1.__decorate([
    (0, graphql_1.Mutation)(() => user_type_1.ActivationResponse),
    tslib_1.__param(0, (0, graphql_1.Args)('activationDto')),
    tslib_1.__param(1, (0, graphql_1.Context)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [typeof (_d = typeof restaurant_dto_1.ActivationDto !== "undefined" && restaurant_dto_1.ActivationDto) === "function" ? _d : Object, Object]),
    tslib_1.__metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], RestaurantResolver.prototype, "activateRestaurant", null);
tslib_1.__decorate([
    (0, graphql_1.Mutation)(() => user_type_1.LoginResponse),
    tslib_1.__param(0, (0, graphql_1.Args)('email')),
    tslib_1.__param(1, (0, graphql_1.Args)('password')),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [String, String]),
    tslib_1.__metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], RestaurantResolver.prototype, "LoginRestaurant", null);
tslib_1.__decorate([
    (0, graphql_1.Query)(() => user_type_1.LoginResponse),
    (0, common_1.UseGuards)(auth_guard_1.AuthGuard),
    tslib_1.__param(0, (0, graphql_1.Context)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object]),
    tslib_1.__metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], RestaurantResolver.prototype, "getLoggedInRestaurant", null);
tslib_1.__decorate([
    (0, graphql_1.Query)(() => user_type_1.LogoutResposne),
    (0, common_1.UseGuards)(auth_guard_1.AuthGuard),
    tslib_1.__param(0, (0, graphql_1.Context)()),
    tslib_1.__metadata("design:type", Function),
    tslib_1.__metadata("design:paramtypes", [Object]),
    tslib_1.__metadata("design:returntype", Promise)
], RestaurantResolver.prototype, "logOutRestaurant", null);
exports.RestaurantResolver = RestaurantResolver = tslib_1.__decorate([
    (0, graphql_1.Resolver)('Restaurant'),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof restaurant_service_1.RestaurantService !== "undefined" && restaurant_service_1.RestaurantService) === "function" ? _a : Object])
], RestaurantResolver);


/***/ }),
/* 20 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LogoutResposne = exports.LoginResponse = exports.ActivationResponse = exports.RegisterResponse = exports.ErrorType = void 0;
const tslib_1 = __webpack_require__(4);
const graphql_1 = __webpack_require__(7);
const restaurant_entities_1 = __webpack_require__(21);
let ErrorType = class ErrorType {
};
exports.ErrorType = ErrorType;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], ErrorType.prototype, "message", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)({ nullable: true }),
    tslib_1.__metadata("design:type", String)
], ErrorType.prototype, "code", void 0);
exports.ErrorType = ErrorType = tslib_1.__decorate([
    (0, graphql_1.ObjectType)()
], ErrorType);
let RegisterResponse = class RegisterResponse {
};
exports.RegisterResponse = RegisterResponse;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], RegisterResponse.prototype, "message", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(() => ErrorType, { nullable: true }),
    tslib_1.__metadata("design:type", ErrorType)
], RegisterResponse.prototype, "error", void 0);
exports.RegisterResponse = RegisterResponse = tslib_1.__decorate([
    (0, graphql_1.ObjectType)()
], RegisterResponse);
let ActivationResponse = class ActivationResponse {
};
exports.ActivationResponse = ActivationResponse;
tslib_1.__decorate([
    (0, graphql_1.Field)(() => restaurant_entities_1.Restaurant),
    tslib_1.__metadata("design:type", Object)
], ActivationResponse.prototype, "restaurant", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(() => ErrorType, { nullable: true }),
    tslib_1.__metadata("design:type", ErrorType)
], ActivationResponse.prototype, "error", void 0);
exports.ActivationResponse = ActivationResponse = tslib_1.__decorate([
    (0, graphql_1.ObjectType)()
], ActivationResponse);
let LoginResponse = class LoginResponse {
};
exports.LoginResponse = LoginResponse;
tslib_1.__decorate([
    (0, graphql_1.Field)(() => restaurant_entities_1.Restaurant, { nullable: true }),
    tslib_1.__metadata("design:type", Object)
], LoginResponse.prototype, "restaurant", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)({ nullable: true }),
    tslib_1.__metadata("design:type", String)
], LoginResponse.prototype, "accessToken", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)({ nullable: true }),
    tslib_1.__metadata("design:type", String)
], LoginResponse.prototype, "refreshToken", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(() => ErrorType, { nullable: true }),
    tslib_1.__metadata("design:type", ErrorType)
], LoginResponse.prototype, "error", void 0);
exports.LoginResponse = LoginResponse = tslib_1.__decorate([
    (0, graphql_1.ObjectType)()
], LoginResponse);
let LogoutResposne = class LogoutResposne {
};
exports.LogoutResposne = LogoutResposne;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], LogoutResposne.prototype, "message", void 0);
exports.LogoutResposne = LogoutResposne = tslib_1.__decorate([
    (0, graphql_1.ObjectType)()
], LogoutResposne);


/***/ }),
/* 21 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Restaurant = exports.Avatars = void 0;
const tslib_1 = __webpack_require__(4);
const graphql_1 = __webpack_require__(7);
let Avatars = class Avatars {
};
exports.Avatars = Avatars;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Avatars.prototype, "id", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Avatars.prototype, "public_id", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Avatars.prototype, "url", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Avatars.prototype, "sellerId", void 0);
exports.Avatars = Avatars = tslib_1.__decorate([
    (0, graphql_1.ObjectType)(),
    (0, graphql_1.Directive)('@key(fields:"id")')
], Avatars);
let Restaurant = class Restaurant {
};
exports.Restaurant = Restaurant;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Restaurant.prototype, "id", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Restaurant.prototype, "name", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Restaurant.prototype, "country", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Restaurant.prototype, "city", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Restaurant.prototype, "address", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Restaurant.prototype, "email", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(() => Avatars, { nullable: true }),
    tslib_1.__metadata("design:type", Avatars)
], Restaurant.prototype, "avatar", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", Number)
], Restaurant.prototype, "phone_number", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", String)
], Restaurant.prototype, "password", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], Restaurant.prototype, "createdAt", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    tslib_1.__metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], Restaurant.prototype, "updatedAt", void 0);
exports.Restaurant = Restaurant = tslib_1.__decorate([
    (0, graphql_1.ObjectType)()
], Restaurant);


/***/ }),
/* 22 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginDto = exports.ActivationDto = exports.RegisterDto = void 0;
const tslib_1 = __webpack_require__(4);
const graphql_1 = __webpack_require__(7);
const class_validator_1 = __webpack_require__(23);
let RegisterDto = class RegisterDto {
};
exports.RegisterDto = RegisterDto;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Restaurant Name is required.' }),
    (0, class_validator_1.IsString)({ message: 'Restaurant Name must need to be one string.' }),
    tslib_1.__metadata("design:type", String)
], RegisterDto.prototype, "name", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Restaurant country is required.' }),
    (0, class_validator_1.IsString)({ message: 'Restaurant country must need to be one string.' }),
    tslib_1.__metadata("design:type", String)
], RegisterDto.prototype, "country", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Restaurant city is required.' }),
    (0, class_validator_1.IsString)({ message: 'Restaurant city must need to be one string.' }),
    tslib_1.__metadata("design:type", String)
], RegisterDto.prototype, "city", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Restaurant city is required.' }),
    (0, class_validator_1.IsString)({ message: 'Restaurant city must need to be one string.' }),
    tslib_1.__metadata("design:type", String)
], RegisterDto.prototype, "address", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Restaurant Email is required.' }),
    (0, class_validator_1.IsEmail)({}, { message: 'Restaurant Email is invalid.' }),
    tslib_1.__metadata("design:type", String)
], RegisterDto.prototype, "email", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Restaurant Phone Number is required.' }),
    tslib_1.__metadata("design:type", Number)
], RegisterDto.prototype, "phone_number", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Restaurant Password is required.' }),
    (0, class_validator_1.MinLength)(8, {
        message: 'Restaurant Password must be at least 8 characters.',
    }),
    tslib_1.__metadata("design:type", String)
], RegisterDto.prototype, "password", void 0);
exports.RegisterDto = RegisterDto = tslib_1.__decorate([
    (0, graphql_1.InputType)()
], RegisterDto);
let ActivationDto = class ActivationDto {
};
exports.ActivationDto = ActivationDto;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Activation Token is required.' }),
    tslib_1.__metadata("design:type", String)
], ActivationDto.prototype, "activationToken", void 0);
exports.ActivationDto = ActivationDto = tslib_1.__decorate([
    (0, graphql_1.InputType)()
], ActivationDto);
let LoginDto = class LoginDto {
};
exports.LoginDto = LoginDto;
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Email is required.' }),
    (0, class_validator_1.IsEmail)({}, { message: 'Email must be valid.' }),
    tslib_1.__metadata("design:type", String)
], LoginDto.prototype, "email", void 0);
tslib_1.__decorate([
    (0, graphql_1.Field)(),
    (0, class_validator_1.IsNotEmpty)({ message: 'Password is required.' }),
    tslib_1.__metadata("design:type", String)
], LoginDto.prototype, "password", void 0);
exports.LoginDto = LoginDto = tslib_1.__decorate([
    (0, graphql_1.InputType)()
], LoginDto);


/***/ }),
/* 23 */
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),
/* 24 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthGuard = void 0;
const tslib_1 = __webpack_require__(4);
const common_1 = __webpack_require__(5);
const graphql_1 = __webpack_require__(7);
const jwt_1 = __webpack_require__(9);
const config_1 = __webpack_require__(6);
const prisma_service_1 = __webpack_require__(10);
let AuthGuard = class AuthGuard {
    constructor(jwtService, prisma, config) {
        this.jwtService = jwtService;
        this.prisma = prisma;
        this.config = config;
    }
    async canActivate(context) {
        const gqlContext = graphql_1.GqlExecutionContext.create(context);
        const { req } = gqlContext.getContext();
        const accessToken = req.headers.accesstoken;
        const refreshToken = req.headers.refreshtoken;
        if (!accessToken || !refreshToken) {
            throw new common_1.UnauthorizedException('Please login to access this resource!');
        }
        if (accessToken) {
            const decoded = this.jwtService.verify(accessToken, {
                ignoreExpiration: true,
                secret: this.config.get('ACCESS_TOKEN_SECRET'),
            });
            if (decoded?.exp * 1000 < Date.now()) {
                await this.updateAccessToken(req);
            }
        }
        return true;
    }
    async updateAccessToken(req) {
        try {
            const refreshTokenData = req.headers.refreshtoken;
            const decoded = this.jwtService.verify(refreshTokenData, {
                secret: this.config.get('REFRESH_TOKEN_SECRET'),
            });
            const expirationTime = decoded.exp * 1000;
            if (expirationTime < Date.now()) {
                throw new common_1.UnauthorizedException('Please login to access this resource!');
            }
            const restaurant = await this.prisma.restaurant.findUnique({
                where: {
                    id: decoded.id,
                },
            });
            const accessToken = this.jwtService.sign({ id: restaurant.id }, {
                secret: this.config.get('ACCESS_TOKEN_SECRET'),
                expiresIn: '1m',
            });
            const refreshToken = this.jwtService.sign({ id: restaurant.id }, {
                secret: this.config.get('REFRESH_TOKEN_SECRET'),
                expiresIn: '7d',
            });
            req.accesstoken = accessToken;
            req.refreshtoken = refreshToken;
            req.restaurant = restaurant;
        }
        catch (error) {
            throw new common_1.UnauthorizedException(error.message);
        }
    }
};
exports.AuthGuard = AuthGuard;
exports.AuthGuard = AuthGuard = tslib_1.__decorate([
    (0, common_1.Injectable)(),
    tslib_1.__metadata("design:paramtypes", [typeof (_a = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _a : Object, typeof (_b = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _b : Object, typeof (_c = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _c : Object])
], AuthGuard);


/***/ })
/******/ 	]);
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(1);
const path_1 = __webpack_require__(2);
const restaurant_module_1 = __webpack_require__(3);
async function bootstrap() {
    const app = await core_1.NestFactory.create(restaurant_module_1.restaurantModule);
    app.useStaticAssets((0, path_1.join)(__dirname, '..', 'public'));
    app.setBaseViewsDir((0, path_1.join)(__dirname, '..', 'apps/api-restuarants/email-templates'));
    app.setViewEngine('ejs');
    app.enableCors({
        origin: '*',
    });
    await app.listen(4001);
}
bootstrap();

})();

var __webpack_export_target__ = exports;
for(var i in __webpack_exports__) __webpack_export_target__[i] = __webpack_exports__[i];
if(__webpack_exports__.__esModule) Object.defineProperty(__webpack_export_target__, "__esModule", { value: true });
/******/ })()
;