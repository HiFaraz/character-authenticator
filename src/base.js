'use strict';

/**
 * Module dependencies.
 */

import { INTERNAL_SERVER_ERROR, NOT_FOUND, SEE_OTHER } from 'http-codes';
import { clone, forEach } from 'lodash';
import { Router } from 'express';
import asyncpipe from 'asyncpipe';
import capitalize from 'capitalize';
import { STATUS_CODES as httpCodeMessage } from 'http';
import queryString from 'querystring';

module.exports = class BaseAuthenticator {
  /**
   * Do not override the constructor, use define and extend instead
   *
   * @param {string} name
   * @param {Object} config
   * @param {Object} deps
   * @param {Object} character
   */
  constructor(name, config, deps, character) {
    this.debug = require('debug')(
      `character:authentication:authenticator:${name}`,
    );

    this.character = character;
    this.config = clone(config);
    this.deps = deps;
    this.name = name;

    this.router = Router();

    this.debug('initializing');

    this.attachModels();
    this.define();
    this.extend();
  }

  /**
   * Attach authenticator models to the context for easy access
   */
  attachModels() {
    const prefix = `Authentication$${capitalize(this.name)}$`;
    this.models = {};
    forEach(this.character.database.models, (model, name) => {
      if (name.startsWith(prefix)) {
        this.models[name.slice(prefix.length)] = model;
      }
    });
  }

  /**
   * Handles requests from the client to the authenticator
   *
   * Override this with a function to define an authenticator route
   *
   * @param {Object} context
   * @param {IncomingMessage} context.req
   * @param {ServerResponse} context.res
   */
  authenticate({ req, res }) {
    /**
     * Example code:
     *
     * return { id: ... };
     */
    const error = new Error(
      `Authenticator#authenticate must be subclassed. My name: ${this.name}`,
    );
    error.httpStatusCode = INTERNAL_SERVER_ERROR;
    throw error;
  }

  /**
   * Define core routes
   *
   * Override this in the internal authenticator to define core routes
   */
  define() {
    /**
     * Example code:
     *
     * this.router.post(...);
     */
    throw new Error('Authenticator#define must be overriden by subclass');
  }

  /**
   * Define extra authenticator routes/behaviour, optional
   *
   * Override this in the custom authenticator to define extra authenticator routes, if desired
   */
  extend() {
    /**
     * Example code:
     *
     * this.router.post(...);
     */
  }

  /**
   * Find the core identity linked to an authenticator account
   *
   * @param {Object} account
   * @param {integer} account.id
   * @return {Promise<Object>}
   */
  findIdentity(account) {
    // TODO similar to authenticators, make it easier for plugins to access their own models. Create this in `CorePlugin`
    const {
      Authentication$Account,
      Core$Identity,
    } = this.character.database.models;
    // TODO plugins shouldn't perform operations on Core$Identity - these should be services from the framework
    return Core$Identity.findOne({
      attributes: ['id'],
      include: [
        {
          attributes: [],
          model: Authentication$Account,
          where: {
            authenticatorAccountId: account.id, // authenticator must return an id
            authenticatorName: this.name,
          },
        },
      ],
      raw: true,
    });
  }

  /**
   * Identity or onboard the authenticator account
   *
   * @param {Object} context
   * @param {Object} context.account
   * @param {IncomingMessage} context.req
   * @param {ServerResponse} context.res
   * @return {Promise<Object>}
   */
  async identify({ account, req, res }) {
    this.debug('got account', account);

    const user = {
      authenticator: {
        account,
        name: this.name,
      },
    };

    if (account.deferred) {
      user.deferred = true;
    } else {
      // TODO if the user is already logged in, consider linking the authenticator account to the logged in core identity instead of creating a new core identity
      const identity = await this.findIdentity(account);

      // `account` is the user record with the authenticator (local or external identity provider)
      // `identity` is the user record with Character

      if (identity) {
        // return the minimum to record successful authentication, rest can be queried by applications later
        user.id = identity.id;
      } else if (this.config.onboardKnownAccounts) {
        // onboard the user by creating a core identity
        const newIdentity = await this.onboard(account);
        user.id = newIdentity.id;
      } else {
        // only accept recognized core identities
        const error = new Error('Could not find identity for account');
        error.httpStatusCode = NOT_FOUND;
        throw error;
      }
    }
    this.character.emit('authentication:authenticate', {
      datetime: new Date(),
      user,
    });
    return { req, res, user };
  }

  /**
   * Create a new core identity linked to an authenticator account
   *
   * @param {Object} account
   * @param {integer} account.id
   * @return {Promise<Object>}
   */
  async onboard(account) {
    // TODO similar to authenticators, make it easier for plugins to access their own models. Create this in `CorePlugin`
    const {
      Authentication$Account,
      Core$Identity,
    } = this.character.database.models;
    const identity = (await Core$Identity.create(
      {
        authentication$Accounts: [
          {
            authenticatorAccountId: account.id,
            authenticatorName: this.name,
          },
        ],
      },
      {
        include: [Authentication$Account],
      },
    )).get({ plain: true });
    this.character.emit('authentication:onboard', {
      account,
      datetime: new Date(),
      identity,
    });
    return identity;
  }

  /**
   * Handle requests from the application to the client
   *
   * @param {IncomingMessage} req
   * @param {ServerResponse} res
   * @return {Promise<Object>}
   */
  async receiver(req, res) {
    try {
      this.debug('enter app request handler');

      return await asyncpipe(
        context => this.authenticate(context),
        context => this.identify(context),
        // login the user by creating a session
        context => {
          if (!context.user.deferred) {
            // deferred can be used by magic link authenticators, which use a non-HTTP protocol (e.g. email) to deliver the magic link
            req.character.set({ user: context.user });
          }
          return context;
        },
        // redirect the user
        context =>
          context.res.redirect(
            SEE_OTHER,
            context.user.deferred
              ? this.config.deferredRedirect
              : this.config.successRedirect,
          ),
      )({ req, res });
    } catch (error) {
      this.debug('error authenticating', error);
      const query = queryString.stringify({
        reason: httpCodeMessage[error.httpStatusCode || INTERNAL_SERVER_ERROR],
      });
      return res.redirect(SEE_OTHER, `${this.config.failureRedirect}?${query}`);
    }
  }

  /**
   * Override this to return authenticator defaults
   *
   * @return {Object}
   */
  static defaults() {
    return {};
  }

  /**
   * Define authenticator models
   *
   * Override this to return authenticator models
   *
   * @return {Object}
   */
  static models() {
    /**
     * Each model must implement some or all of the standard interface below
     *
     * Example code:
     *
     * return {
     *   modelName: {
     *     associate: models => {},
     *     attributes: {},
     *     define: Model => {},
     *     options: {},
     *   },
     * }
     */
    return {};
  }
};
