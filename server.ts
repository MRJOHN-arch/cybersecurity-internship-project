/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import i18n from 'i18n'
import cors from 'cors'
import fs from 'node:fs'
import yaml from 'js-yaml'
import config from 'config'
import morgan from 'morgan'
import multer from 'multer'
import helmet from 'helmet'
import http from 'node:http'
import path from 'node:path'
import express from 'express'
import colors from 'colors/safe'
import serveIndex from 'serve-index'
import bodyParser from 'body-parser'
// @ts-expect-error FIXME due to non-existing type definitions for finale-rest
import * as finale from 'finale-rest'
import compression from 'compression'
// @ts-expect-error FIXME due to non-existing type definitions for express-robots-txt
import robots from 'express-robots-txt'
import cookieParser from 'cookie-parser'
import * as Prometheus from 'prom-client'
import swaggerUi from 'swagger-ui-express'
import featurePolicy from 'feature-policy'
import { IpFilter } from 'express-ipfilter'
// @ts-expect-error FIXME due to non-existing type definitions for express-security.txt
import securityTxt from 'express-security.txt'
import { rateLimit } from 'express-rate-limit'
import { getStream } from 'file-stream-rotator'
import type { Request, Response, NextFunction } from 'express'

import * as winston from 'winston' // <-- NEW: Import Winston
import { sequelize } from './models'
import { UserModel } from './models/user'
import { ProductModel } from './models/product'
import { BasketModel } from './models/basket'
import { BasketItemModel } from './models/basketitem'
import { AddressModel } from './models/address'
import { CardModel } from './models/card'
import { QuantityModel } from './models/quantity'
import { FeedbackModel } from './models/feedback'
import { ImageModel } from './models/image'
import { ChallengeModel } from './models/challenge'
import { ComplaintModel } from './models/complaint'
import { RecyclerModel } from './models/recycler'
import { DeliveryModel } from './models/delivery'
import { WalletModel } from './models/wallet'
import { PrivacyRequestModel } from './models/privacyRequest'
import { DiscountModel } from './models/discount'
import { SnitchModel } from './models/snitch'

import logger from './lib/logger' // NOTE: This is the old logger, we will use the new one below
import * as utils from './lib/utils'
import * as routes from './routes/index'
import * as security from './lib/insecurity'
import * as metrics from './lib/metrics'
import * as models from './models'
import { customizeApplication } from './lib/customize'
import { customizeEasterEgg } from './lib/customizations/easterEgg'
import { collectDurationPromise } from './lib/metrics'
import * as prometheus from './lib/prometheus'
import { registerWebsocketEvents } from './lib/websocket'

import {
  continueCodeBenderFlow,
  serveCodeBender
} from './routes/continueCodeBenderFlow'
import { retrieveChallenge } from './routes/retrieveChallenge'
import { errorReport } from './routes/errorReport'
import { image } from './routes/image'
import { redirect } from './routes/redirect'
import { video } from './routes/video'
import { coupon } from './routes/coupon'
import { twoFactorAuth } from './routes/twoFactorAuth'
import { lastWish } from './routes/lastWish'
import { profile } from './routes/profile'
import { trust } from './routes/trust'
import { wellKnown } from './routes/wellKnown'
import { restoreProgress } from './routes/restoreProgress'
import { changePassword } from './routes/changePassword'
import { resetPassword } from './routes/resetPassword'
import { search } from './routes/search'
import { main } from './routes/main'
import { angular } from './routes/angular'
import { login } from './routes/login'
import { trackOrder } from './routes/trackOrder'
import { b2bOrder } from './routes/b2bOrder'
import { administration } from './routes/administration'
import { bulkFeedback } from './routes/bulkFeedback'
import { fileUpload } from './routes/fileUpload'
import { serveMetrics } from './routes/metrics'
import { graphqlQuery } from './routes/graphqlQuery'
import { logWinston } from './routes/logWinston'
import { userInfo } from './routes/userInfo'
import { appVersion } from './routes/appVersion'
import { apiVersion } from './routes/apiVersion'
import { swagger } from './routes/swagger'
import { serveJsonFile } from './routes/serveJsonFile'
import { buy } from './routes/buy'
import { orderPayment } from './routes/orderPayment'
import { orderHistory } from './routes/orderHistory'
import { get_and_create_captcha } from './routes/captcha'

import { registerBasketRoutes } from './routes/basket'
import { registerProductRoutes } from './routes/product'
import { registerBasketItemRoutes } from './routes/basketitem'
import { registerAddressRoutes } from './routes/address'
import { registerCardRoutes } from './routes/card'
import { registerQuantityRoutes } from './routes/quantity'
import { registerFeedbackRoutes } from './routes/feedback'
import { registerImageRoutes } from './routes/image'
import { registerChallengeRoutes } from './routes/challenge'
import { registerComplaintRoutes } from './routes/complaint'
import { registerRecyclerRoutes } from './routes/recycler'
import { registerDeliveryRoutes } from './routes/delivery'
import { registerWalletRoutes } from './routes/wallet'
import { registerPrivacyRequestRoutes } from './routes/privacyRequest'
import { registerDiscountRoutes } from './routes/discount'
import { registerSnitchRoutes } from './routes/snitch'
import { registerDataExportRoutes } from './routes/dataExport'
import { registerAboutRoutes } from './routes/about'
import { registerSourceRoutes } from './routes/source'
import { registerDataBackupRoutes } from './routes/dataBackup'
import { registerMetricsRoutes } from './routes/metrics'
import { registerLoginRoutes } from './routes/login'
import { registerRegisterRoutes } from './routes/register'
import { registerRestoreProgressRoutes } from './routes/restoreProgress'
import { registerTrackOrderRoutes } from './routes/trackOrder'
import { registerOrderRoutes } from './routes/order'
import { registerUserModelRoutes } from './routes/user'

const Metrics = prometheus.Metrics
const fileUploads = multer({ dest: 'uploads/' })
const uploadAccessControl = security.accessControlMiddleware()
const startupGauge = new Prometheus.Gauge({
  name: 'owasp_juice_shop_startup_timestamp_seconds',
  help: 'Timestamp of when the application started.',
  labelNames: ['task']
})
const collectDuration = metrics.collectDuration()
let metricsUpdateLoop: NodeJS.Timeout
const startTime = Date.now()

const app = express()
const server = http.createServer(app)
const { paths } = utils.readJsonStore()

// region Winston Logger Configuration (Week 3, Task 2)
const securityLogger = winston.createLogger({
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({
      filename: 'security.log',
      level: 'info', // Only log 'info' level and above to the file
      format: winston.format.simple()
    })
  ]
})
// We will use securityLogger instead of the original 'logger' for security-related events.
// endregion

// region Sequelize-specific initialisation
const sequelize = models.sequelize
const UserModel = models.UserModel
const ProductModel = models.ProductModel
const BasketModel = models.BasketModel
const BasketItemModel = models.BasketItemModel
const AddressModel = models.AddressModel
const CardModel = models.CardModel
const QuantityModel = models.QuantityModel
const FeedbackModel = models.FeedbackModel
const ImageModel = models.ImageModel
const ChallengeModel = models.ChallengeModel
const ComplaintModel = models.ComplaintModel
const RecyclerModel = models.RecyclerModel
const DeliveryModel = models.DeliveryModel
const WalletModel = models.WalletModel
const PrivacyRequestModel = models.PrivacyRequestModel
const DiscountModel = models.DiscountModel
const SnitchModel = models.SnitchModel
// endregion

// region Configuration-specific initialisation
const applicationName = config.get<string>('application.name')
const configPath = process.env.NODE_ENV === 'e2e' ? 'config/e2e.yml' : 'config/default.yml'
const configContent = yaml.load(fs.readFileSync(configPath, 'utf8')) as Record<string, any>
const configVersion = configContent.version ?? ''
// endregion

// region Global application settings
i18n.configure({
  locales: ['en', 'de'],
  directory: path.join(__dirname, '..', 'i18n'),
  defaultLocale: 'en',
  objectNotation: true,
  updateFiles: false
})
app.use(i18n.init)

/**
 * SECURITY FIX: Secure Data Transmission (Week 2, Task 3)
 * Implemented Helmet.js to secure HTTP headers against common web vulnerabilities.
 * It is placed first to ensure headers are set immediately.
 */
app.use(helmet()) 

app.use(cookieParser('kekse'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(compression())

// region Logging
const morganStream = getStream({
  filename: path.join(__dirname, '..', 'access.log'),
  frequency: 'daily',
  verbose: false
})
app.use(morgan('combined', { stream: morganStream }))
app.use(morgan('dev', { skip: (req: Request, res: Response) => res.statusCode < 400 }))
// endregion

// region Security and Feature Configuration
// app.use(securityTxt()) // Use of featurePolicy overrides default Helmet CSP configuration

// const csp = {
//   directives: {
//     defaultSrc: ["'self'"],
//     scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.jsdelivr.net'],
//     styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
//     fontSrc: ["'self'", 'https://fonts.gstatic.com'],
//     imgSrc: ["'self'", 'data:'],
//     connectSrc: ["'self'"],
//     objectSrc: ["'none'"],
//     mediaSrc: ["'self'"],
//     frameAncestors: ["'none'"]
//   }
// }
// app.use(helmet.contentSecurityPolicy(csp))

// app.use(featurePolicy({
//   features: {
//     payment: ["'none'"],
//     camera: ["'none'"],
//     microphone: ["'none'"],
//     geolocation: ["'none'"]
//   }
// }))

app.use(cors({
  origin: config.get('cors.origin'),
  credentials: config.get('cors.credentials')
}))

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false
})
app.use(limiter)
// endregion

// region Models
UserModel.hasMany(BasketModel, { foreignKey: 'UserId' })
BasketModel.belongsTo(UserModel)
UserModel.hasMany(FeedbackModel, { foreignKey: 'UserId' })
FeedbackModel.belongsTo(UserModel)
BasketModel.hasMany(BasketItemModel, { foreignKey: 'BasketId' })
BasketItemModel.belongsTo(BasketModel)
ProductModel.hasMany(BasketItemModel, { foreignKey: 'ProductId' })
BasketItemModel.belongsTo(ProductModel)
BasketItemModel.hasMany(QuantityModel, { foreignKey: 'BasketItemId' })
QuantityModel.belongsTo(BasketItemModel)
ProductModel.hasMany(ImageModel, { foreignKey: 'ProductId' })
ImageModel.belongsTo(ProductModel)
UserModel.hasMany(AddressModel, { foreignKey: 'UserId' })
AddressModel.belongsTo(UserModel)
UserModel.hasMany(CardModel, { foreignKey: 'UserId' })
CardModel.belongsTo(UserModel)
UserModel.hasMany(ComplaintModel, { foreignKey: 'UserId' })
ComplaintModel.belongsTo(UserModel)
UserModel.hasMany(RecyclerModel, { foreignKey: 'UserId' })
RecyclerModel.belongsTo(UserModel)
DeliveryModel.hasMany(BasketModel, { foreignKey: 'DeliveryId' })
BasketModel.belongsTo(DeliveryModel)
UserModel.hasMany(WalletModel, { foreignKey: 'UserId' })
WalletModel.belongsTo(UserModel)
UserModel.hasMany(PrivacyRequestModel, { foreignKey: 'UserId' })
PrivacyRequestModel.belongsTo(UserModel)
DiscountModel.hasMany(ProductModel, { foreignKey: 'DiscountId' })
ProductModel.belongsTo(DiscountModel)
UserModel.hasMany(SnitchModel, { foreignKey: 'UserId' })
SnitchModel.belongsTo(UserModel)

// endregion

// region Routes (GET)
// app.get('/rest/country-mapping', countryMapping()) // vuln-code-snippet hide-line

app.get('/rest/user/:id', userInfo())
app.get('/rest/product/search', search())
app.get('/rest/products/:id', routes.product())
app.get('/rest/continue-code-bender', continueCodeBenderFlow())
app.get('/rest/serve-code-bender', serveCodeBender())
app.get('/rest/snitch/:id', routes.snitch())
app.get('/rest/snitches', registerSnitchRoutes())

// API endpoints
registerBasketRoutes()
registerProductRoutes()
registerBasketItemRoutes()
registerAddressRoutes()
registerCardRoutes()
registerQuantityRoutes()
registerFeedbackRoutes()
registerImageRoutes()
registerChallengeRoutes()
registerComplaintRoutes()
registerRecyclerRoutes()
registerDeliveryRoutes()
registerWalletRoutes()
registerPrivacyRequestRoutes()
registerDiscountRoutes()
registerDataExportRoutes()
registerAboutRoutes()
registerSourceRoutes()
registerDataBackupRoutes()
registerMetricsRoutes()
registerLoginRoutes()
registerRegisterRoutes()
registerRestoreProgressRoutes()
registerTrackOrderRoutes()
registerOrderRoutes()
registerUserModelRoutes()

app.get('/rest/admin/application-version', appVersion())
app.get('/rest/admin/api-version', apiVersion())

app.get('/redirect', redirect()) // vuln-code-snippet find-block
app.get('/video', video())
app.get('/rest/captcha', get_and_create_captcha())
app.get('/rest/track-order/:id', trackOrder())
app.get('/rest/reset-password', resetPassword())
app.get('/rest/retrieve-challenge', retrieveChallenge())
app.get('/rest/code-bender', serveCodeBender()) // vuln-code-snippet neutral-line exposedMetricsChallenge

// swagger documentation endpoint
app.get('/swagger-docs', swagger())
app.get('/swagger-docs/:filename', serveJsonFile())
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(yaml.load(fs.readFileSync(path.join(__dirname, '..', 'swagger.yml'), 'utf8')) as Record<string, any>))

app.use('/public/ftp', serveIndex('ftp', { 'icons': true }))
app.use('/public/ftp', express.static('ftp'))

app.use('/public/images', express.static(path.join(__dirname, '..', 'frontend/dist/frontend/assets/public/images')))

// region Static Content
const contentPath = path.join(__dirname, '..', 'frontend/dist/frontend')
app.use(express.static(contentPath))
// endregion

app.use(robots({
  UserAgent: '*',
  Disallow: '/',
  sitemap: `${config.get<string>('server.basePath')}/public/sitemap.xml`
}))

app.use('/frontend/dist', express.static(path.join(__dirname, '..', 'frontend/dist')))

app.get('/main.js', main())
app.get('/main.css', angular())

// region Routes (POST)
app.post('/rest/user/login', login()) // vuln-code-snippet hide-line
app.post('/rest/user/change-password', changePassword())
app.post('/rest/user/reset-password', resetPassword())

app.post('/rest/two-factor-auth', twoFactorAuth())
app.post('/rest/basket/:id/order', orderPayment())
app.post('/rest/order-history', orderHistory())
app.post('/rest/order', routes.order())
app.post('/rest/buy', buy())

app.post('/rest/feedback', routes.feedback())
app.post('/rest/file-upload', uploadAccessControl, fileUploads.single('file'), fileUpload())
app.post('/rest/report', errorReport())
app.post('/rest/restore-progress', restoreProgress())
app.post('/rest/coupon/:id', coupon())
app.post('/rest/b2b/order', b2bOrder())
app.post('/rest/graphql', graphqlQuery())
app.post('/rest/log', logWinston())
// endregion

// region Image manipulation
app.get('/image', image()) // vuln-code-snippet hide-line
// endregion

// region Last wish
app.get('/last-wish', lastWish())
app.get('/profile', profile())
// endregion

// region Trust
app.get('/trust', trust())
// endregion

// region Administration
app.get('/administration', administration())
// endregion

// region Well-known (A/B testing)
app.get('/.well-known/apple-app-site-association', wellKnown())
// endregion

// region Health Check and Metrics
app.get('/metrics', serveMetrics()) // vuln-code-snippet hide-line
// endregion

// region Custom 404
app.use('*', angular()) // Default redirect to Angular app
// endregion

// region Error handling
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  // Use the default error logger (logger) for critical errors
  logger.error(err.message)
  res.status(err.status ?? 500).send(res.__('server_error'))
})
// endregion

// region Start server
export async function start (readyCallback?: () => void) {
  const datacreatorEnd = startupGauge.startTimer({ task: 'datacreator' })
  await sequelize.sync({ force: true })
  await routes.datacreator()
  datacreatorEnd()
  const port = process.env.PORT ?? config.get('server.port')
  process.env.BASE_PATH = process.env.BASE_PATH ?? config.get('server.basePath')

  metricsUpdateLoop = Metrics.updateLoop() // vuln-code-snippet neutral-line exposedMetricsChallenge

  server.listen(port, () => {
    // NEW: Use winston logger for application start-up event logging
    securityLogger.info(colors.cyan(`Application started on port ${colors.bold(`${port}`)}`))
    securityLogger.info(`Logging security events to ${path.resolve('security.log')}`)
    // END NEW

    logger.info(colors.cyan(`Server listening on port ${colors.bold(`${port}`)}`))
    startupGauge.set({ task: 'ready' }, (Date.now() - startTime) / 1000)
    if (process.env.BASE_PATH !== '') {
      logger.info(colors.cyan(`Server using proxy base path ${colors.bold(`${process.env.BASE_PATH}`)} for redirects`))
    }
    registerWebsocketEvents(server)
    if (readyCallback) {
      readyCallback()
    }
  })

  void collectDurationPromise('customizeApplication', customizeApplication)() // vuln-code-snippet hide-line
  void collectDurationPromise('customizeEasterEgg', customizeEasterEgg)() // vuln-code-snippet hide-line
}

export function close (exitCode: number | undefined) {
  if (server) {
    clearInterval(metricsUpdateLoop)
    server.close()
  }
  if (exitCode !== undefined) {
    process.exit(exitCode)
  }
}
