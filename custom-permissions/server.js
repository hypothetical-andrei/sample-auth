const express = require('express')
const Sequelize = require('sequelize')
const bodyParser = require('body-parser')
const moment = require('moment')
const crypto = require('crypto')

const sequelize = new Sequelize('node_security', 'app1', 'welcome123', {
	dialect : 'mysql'
})

const User = sequelize.define('user', {
  username: Sequelize.STRING,
  password: Sequelize.STRING,
  token: Sequelize.STRING,
  expiry: Sequelize.DATE,
  userType: Sequelize.STRING
})

const Resource = sequelize.define('resource', {
  content: Sequelize.STRING
})

const Permission = sequelize.define('permission', {
  permType: Sequelize.ENUM('read')
})

User.hasMany(Permission)
Resource.hasMany(Permission)

const app = express()

const adminRouter = express.Router()
const apiRouter = express.Router()
const authRouter = express.Router()

app.use(bodyParser.json())

apiRouter.use(async (req, res, next) => {
  try {
    const token = req.headers.auth ? req.headers.auth : ''
    const user = await User.findOne({
      where: {
        token: token
      }
    })
    if (user) {
      if (moment().diff(user.expiry, 'seconds') < 0) {
        res.locals.user = user
        next()
      } else {
        res.status(401).json({ message: 'token expired' })
      }
    } else {
      res.status(401).json({ message: 'you need a valid token' })
    }
  } catch (err) {
    next(err)
  }
})

apiRouter.use(async (req, res, next) => {
  try {
    const user = res.locals.user
    if (user.userType === 'special') {
      next()
    } else {
      res.status(401).json({ message: 'you have to be special to pass' })
    }
  } catch (err) {
    next(err)
  }
})

const perm = (rid) => {
  const middleware = async (req, res, next) => {
    try {
      const userId = res.locals.user.id
      const resourceId = req.params[rid]
      const permission = await Permission.findOne({
        where: {
          resourceId: resourceId,
          userId: userId
        }
      })
      if (permission) {
        next()
      } else {
        res.status(401).json({ message: 'this is not your resource' })
      }
    } catch (err) {
      next(err)
    }
  }
  return middleware
}

authRouter.post('/login', async (req, res, next) => {
  const credentials = req.body
  try {
    const user = await User.findOne({
      where: {
        username: credentials.username,
        password: credentials.password
      }
    })
    if (user) {
      const token = crypto.randomBytes(64).toString('hex')
      user.token = token
      user.expiry = moment().add(600, 'seconds')
      await user.save()
      res.status(200).json({ token: token })
    } else {
      res.status(401).json({ message: 'credentials invalid' }) 
    }
  } catch (err) {
    next(err)
  }
})

adminRouter.get('/create', async (req, res, next) => {
  try {
    await sequelize.sync({ force: true })
    await User.create({
      username: 'user1',
      password: 'pass1',
      userType: 'special'
    })
    await User.create({
      username: 'user2',
      password: 'pass2',
      userType: 'special'
    })
    res.status(201).json({ message: 'created' })
  } catch (err) {
    next(err)
  }
})

adminRouter.post('/users', async (req, res, next) => {
  try {
    await User.create(req.body)
    res.status(201).json({ message: 'created' })
  } catch (err) {
    next(err)
  }
})

adminRouter.post('/perms', async (req, res, next) => {
  try {
    await Permission.create(req.body)
    res.status(201).json({ message: 'created' })
  } catch (err) {
    next(err)
  }
})

apiRouter.get('/test', (req, res, next) => {
	res.status(200).json({ message: 'you are in '})
})

apiRouter.post('/users/:uid/resources', async (req, res, next) => {
  try {
    const user = res.locals.user
    const resource = await Resource.create(req.body)
    const permission = new Permission()
    permission.permType = 'read'
    permission.userId = user.id
    permission.resourceId = resource.id
    await permission.save()
    res.status(201).json({ message: 'created' })
  } catch (err) {
    next(err)
  }
})

apiRouter.get('/users/:uid/resources/:rid', perm('rid'), async (req, res, next) => {
  try {
    const resource = await Resource.findByPk(req.params.rid)
    if (resource) {
      res.status(200).json(resource)
    } else {
      res.status(404).json({ message: 'not found' })
    }
  } catch (err) {
    next(err)
  }
})

app.use('/admin', adminRouter)
app.use('/api', apiRouter)
app.use('/auth', authRouter)

app.use((err, req, res, next) => {
  console.warn(err)
  res.status(500).json({ message: 'something happened' })
})

app.listen(8080)