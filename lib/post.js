'use strict';

/**
 * Module dependencies.
 */

const BaseAuthenticator = require('./base');

module.exports = class POSTAuthenticator extends BaseAuthenticator {
  /**
   * Define core routes
   */
  define() {
    this.router.post('/', this.deps.session, (req, res, next) =>
      this.receiver(req, res, next),
    );
  }
};
