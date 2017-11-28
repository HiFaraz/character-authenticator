'use strict';

/**
 * Module dependencies.
 */

import BaseAuthenticator from './base';

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
