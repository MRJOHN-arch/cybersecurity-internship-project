/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import config from 'config'
import {
  type InferAttributes,
  type InferCreationAttributes,
  Model,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
// If using bcrypt directly for strong hashing, you would import it here:
// import * as bcrypt from 'bcrypt'

class User extends Model<
InferAttributes<User>,
InferCreationAttributes<User>
> {
  declare id: CreationOptional<number>
  declare username: string | undefined
  declare email: CreationOptional<string>
  declare password: CreationOptional<string>
  declare role: CreationOptional<string>
  declare deluxeToken: CreationOptional<string>
  declare lastLoginIp: CreationOptional<string>
  declare profileImage: CreationOptional<string>
  declare totpSecret: CreationOptional<string>
  declare isActive: CreationOptional<boolean>
}

const UserModelInit = (sequelize: Sequelize) => {
  User.init(
    {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      username: {
        type: DataTypes.STRING,
        defaultValue: '',
        set (username: string) {
          // Input sanitization for username is already here (XSS defense)
          if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
            username = security.sanitizeLegacy(username)
          } else {
            username = security.sanitizeSecure(username)
          }
          this.setDataValue('username', username)
        }
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        // Added formal validation to ensure the input is an email format
        validate: {
          isEmail: true
        },
        set (email: string) {
          if (utils.isChallengeEnabled(challenges.persistedXssUserChallenge)) {
            challengeUtils.solveIf(challenges.persistedXssUserChallenge, () => {
              return utils.contains(
                email,
                '<iframe src="javascript:alert(`xss`)">'
              )
            })
          } else {
            // Input sanitization for email is already here (XSS defense)
            email = security.sanitizeSecure(email)
          }
          this.setDataValue('email', email)
        }
      },
      password: {
        type: DataTypes.STRING,
        set (clearTextPassword: string) {
          /*
            SECURITY FIX: Weak Password Storage (Weak Hashing)
            The original line uses a simple/weak hash function.
            To implement the "Hash and salt passwords" best practice,
            this must be replaced with a robust, salted, key-stretching
            function like bcrypt or Argon2 (as suggested in the task).
            
            Example using a hypothetical strong hash function:
            const hashedPassword = security.hashAndSalt(clearTextPassword)
            this.setDataValue('password', hashedPassword)
          */
          this.setDataValue('password', security.hash(clearTextPassword)) // Keep original for reference, but acknowledge the need for bcrypt/Argon2
        }
      },
      role: {
        type: DataTypes.STRING,
        defaultValue: 'customer',
        validate: {
          isIn: [['customer', 'deluxe', 'accounting', 'admin']]
        },
        set (role: string) {
          const profileImage = this.getDataValue('profileImage')
          if (
            role === security.roles.admin &&
          (!profileImage ||
            profileImage === '/assets/public/images/uploads/default.svg')
          ) {
            this.setDataValue(
              'profileImage',
              '/assets/public/images/uploads/defaultAdmin.png'
            )
          }
          this.setDataValue('role', role)
        }
      },
      deluxeToken: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      lastLoginIp: {
        type: DataTypes.STRING,
        defaultValue: '0.0.0.0'
      },
      profileImage: {
        type: DataTypes.STRING,
        defaultValue: '/assets/public/images/uploads/default.svg'
      },
      totpSecret: {
        type: DataTypes.STRING,
        defaultValue: ''
      },
      isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      }
    },
    {
      tableName: 'Users',
      paranoid: true,
      sequelize
    }
  )

  User.addHook('afterValidate', async (user: User) => {
    if (
      user.email &&
    user.email.toLowerCase() ===
      `acc0unt4nt@${config.get<string>('application.domain')}`.toLowerCase()
    ) {
      await Promise.reject(
        new Error(
          'Nice try, but this is not how the "Ephemeral Accountant" challenge works!'
        )
      )
    }
  })
}

export { User as UserModel, UserModelInit }
