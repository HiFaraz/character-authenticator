/**
 * This file is reserved for future development
 *
 * Not ready for use
 */
'use strict';

/**
 * Module dependencies.
 */

const BaseAuthenticator = require('./base');

module.exports = class GETAuthenticator extends BaseAuthenticator {
  /**
   * Define core routes
   */
  define() {
    this.router.get('/', this.deps.session, (req, res, next) =>
      this.receiver(req, res, next),
    );

    this.router.get('/callback', this.deps.session, (req, res, next) =>
      this.callback(req, res, next),
    );
  }
};
